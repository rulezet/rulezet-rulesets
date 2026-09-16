rule TTP_XOR_MULT_DOSStub_0905 {
  strings:
    $key_0905 = { 5d 6d [2] 29 75 [2] 6e 77 [2] 29 66 [2] 67 6a [2] 6b 60 [2] 7c 6b [2] 67 25 [2] 5a }

  condition:
    any of them
}