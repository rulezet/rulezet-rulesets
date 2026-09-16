rule TTP_XOR_MULT_DOSStub_7405 {
  strings:
    $key_7405 = { 20 6d [2] 54 75 [2] 13 77 [2] 54 66 [2] 1a 6a [2] 16 60 [2] 01 6b [2] 1a 25 [2] 27 }

  condition:
    any of them
}