rule TTP_XOR_MULT_DOSStub_95c1 {
  strings:
    $key_95c1 = { c1 a9 [2] b5 b1 [2] f2 b3 [2] b5 a2 [2] fb ae [2] f7 a4 [2] e0 af [2] fb e1 [2] c6 }

  condition:
    any of them
}