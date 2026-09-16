rule TTP_XOR_MULT_DOSStub_b0d1 {
  strings:
    $key_b0d1 = { e4 b9 [2] 90 a1 [2] d7 a3 [2] 90 b2 [2] de be [2] d2 b4 [2] c5 bf [2] de f1 [2] e3 }

  condition:
    any of them
}