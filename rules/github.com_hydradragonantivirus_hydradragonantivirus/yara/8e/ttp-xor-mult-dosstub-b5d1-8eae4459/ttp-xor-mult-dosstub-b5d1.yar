rule TTP_XOR_MULT_DOSStub_b5d1 {
  strings:
    $key_b5d1 = { e1 b9 [2] 95 a1 [2] d2 a3 [2] 95 b2 [2] db be [2] d7 b4 [2] c0 bf [2] db f1 [2] e6 }

  condition:
    any of them
}