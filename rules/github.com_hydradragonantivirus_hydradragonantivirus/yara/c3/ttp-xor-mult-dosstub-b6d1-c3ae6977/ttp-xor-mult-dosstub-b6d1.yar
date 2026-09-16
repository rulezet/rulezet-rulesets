rule TTP_XOR_MULT_DOSStub_b6d1 {
  strings:
    $key_b6d1 = { e2 b9 [2] 96 a1 [2] d1 a3 [2] 96 b2 [2] d8 be [2] d4 b4 [2] c3 bf [2] d8 f1 [2] e5 }

  condition:
    any of them
}