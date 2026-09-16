rule TTP_XOR_MULT_DOSStub_a6d1 {
  strings:
    $key_a6d1 = { f2 b9 [2] 86 a1 [2] c1 a3 [2] 86 b2 [2] c8 be [2] c4 b4 [2] d3 bf [2] c8 f1 [2] f5 }

  condition:
    any of them
}