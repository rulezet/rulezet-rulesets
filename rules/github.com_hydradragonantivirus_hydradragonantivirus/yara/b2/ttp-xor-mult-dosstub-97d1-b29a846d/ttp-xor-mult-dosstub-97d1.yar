rule TTP_XOR_MULT_DOSStub_97d1 {
  strings:
    $key_97d1 = { c3 b9 [2] b7 a1 [2] f0 a3 [2] b7 b2 [2] f9 be [2] f5 b4 [2] e2 bf [2] f9 f1 [2] c4 }

  condition:
    any of them
}