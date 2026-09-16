rule TTP_XOR_MULT_DOSStub_b7d1 {
  strings:
    $key_b7d1 = { e3 b9 [2] 97 a1 [2] d0 a3 [2] 97 b2 [2] d9 be [2] d5 b4 [2] c2 bf [2] d9 f1 [2] e4 }

  condition:
    any of them
}