rule TTP_XOR_MULT_DOSStub_d5c1 {
  strings:
    $key_d5c1 = { 81 a9 [2] f5 b1 [2] b2 b3 [2] f5 a2 [2] bb ae [2] b7 a4 [2] a0 af [2] bb e1 [2] 86 }

  condition:
    any of them
}