rule TTP_XOR_MULT_DOSStub_0349 {
  strings:
    $key_0349 = { 57 21 [2] 23 39 [2] 64 3b [2] 23 2a [2] 6d 26 [2] 61 2c [2] 76 27 [2] 6d 69 [2] 50 }

  condition:
    any of them
}