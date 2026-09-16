rule TTP_XOR_MULT_DOSStub_3549 {
  strings:
    $key_3549 = { 61 21 [2] 15 39 [2] 52 3b [2] 15 2a [2] 5b 26 [2] 57 2c [2] 40 27 [2] 5b 69 [2] 66 }

  condition:
    any of them
}