rule TTP_XOR_MULT_DOSStub_0549 {
  strings:
    $key_0549 = { 51 21 [2] 25 39 [2] 62 3b [2] 25 2a [2] 6b 26 [2] 67 2c [2] 70 27 [2] 6b 69 [2] 56 }

  condition:
    any of them
}