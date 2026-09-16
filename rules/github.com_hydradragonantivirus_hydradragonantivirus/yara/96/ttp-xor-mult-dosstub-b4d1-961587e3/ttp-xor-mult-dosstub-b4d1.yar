rule TTP_XOR_MULT_DOSStub_b4d1 {
  strings:
    $key_b4d1 = { e0 b9 [2] 94 a1 [2] d3 a3 [2] 94 b2 [2] da be [2] d6 b4 [2] c1 bf [2] da f1 [2] e7 }

  condition:
    any of them
}