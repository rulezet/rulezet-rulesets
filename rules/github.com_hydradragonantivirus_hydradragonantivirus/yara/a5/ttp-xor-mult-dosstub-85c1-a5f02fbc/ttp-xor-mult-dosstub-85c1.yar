rule TTP_XOR_MULT_DOSStub_85c1 {
  strings:
    $key_85c1 = { d1 a9 [2] a5 b1 [2] e2 b3 [2] a5 a2 [2] eb ae [2] e7 a4 [2] f0 af [2] eb e1 [2] d6 }

  condition:
    any of them
}