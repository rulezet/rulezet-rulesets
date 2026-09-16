rule TTP_XOR_MULT_DOSStub_a7d1 {
  strings:
    $key_a7d1 = { f3 b9 [2] 87 a1 [2] c0 a3 [2] 87 b2 [2] c9 be [2] c5 b4 [2] d2 bf [2] c9 f1 [2] f4 }

  condition:
    any of them
}