rule TTP_XOR_MULT_DOSStub_d549 {
  strings:
    $key_d549 = { 81 21 [2] f5 39 [2] b2 3b [2] f5 2a [2] bb 26 [2] b7 2c [2] a0 27 [2] bb 69 [2] 86 }

  condition:
    any of them
}