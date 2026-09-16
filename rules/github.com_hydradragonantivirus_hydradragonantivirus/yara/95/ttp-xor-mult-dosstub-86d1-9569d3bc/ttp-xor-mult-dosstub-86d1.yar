rule TTP_XOR_MULT_DOSStub_86d1 {
  strings:
    $key_86d1 = { d2 b9 [2] a6 a1 [2] e1 a3 [2] a6 b2 [2] e8 be [2] e4 b4 [2] f3 bf [2] e8 f1 [2] d5 }

  condition:
    any of them
}