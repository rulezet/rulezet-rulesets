rule TTP_XOR_MULT_DOSStub_7905 {
  strings:
    $key_7905 = { 2d 6d [2] 59 75 [2] 1e 77 [2] 59 66 [2] 17 6a [2] 1b 60 [2] 0c 6b [2] 17 25 [2] 2a }

  condition:
    any of them
}