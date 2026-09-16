rule TTP_XOR_MULT_DOSStub_92c1 {
  strings:
    $key_92c1 = { c6 a9 [2] b2 b1 [2] f5 b3 [2] b2 a2 [2] fc ae [2] f0 a4 [2] e7 af [2] fc e1 [2] c1 }

  condition:
    any of them
}