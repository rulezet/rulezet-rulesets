rule TTP_XOR_MULT_DOSStub_7922 {
  strings:
    $key_7922 = { 2d 4a [2] 59 52 [2] 1e 50 [2] 59 41 [2] 17 4d [2] 1b 47 [2] 0c 4c [2] 17 02 [2] 2a }

  condition:
    any of them
}