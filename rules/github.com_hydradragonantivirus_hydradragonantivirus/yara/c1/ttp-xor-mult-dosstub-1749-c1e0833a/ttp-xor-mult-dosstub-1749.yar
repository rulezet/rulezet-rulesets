rule TTP_XOR_MULT_DOSStub_1749 {
  strings:
    $key_1749 = { 43 21 [2] 37 39 [2] 70 3b [2] 37 2a [2] 79 26 [2] 75 2c [2] 62 27 [2] 79 69 [2] 44 }

  condition:
    any of them
}