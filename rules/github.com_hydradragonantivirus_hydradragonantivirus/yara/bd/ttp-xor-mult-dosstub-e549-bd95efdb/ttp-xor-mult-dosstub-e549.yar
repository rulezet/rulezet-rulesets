rule TTP_XOR_MULT_DOSStub_e549 {
  strings:
    $key_e549 = { b1 21 [2] c5 39 [2] 82 3b [2] c5 2a [2] 8b 26 [2] 87 2c [2] 90 27 [2] 8b 69 [2] b6 }

  condition:
    any of them
}