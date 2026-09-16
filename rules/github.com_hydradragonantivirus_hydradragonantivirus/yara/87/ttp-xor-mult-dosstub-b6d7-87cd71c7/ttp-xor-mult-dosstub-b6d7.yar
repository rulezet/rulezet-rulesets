rule TTP_XOR_MULT_DOSStub_b6d7 {
  strings:
    $key_b6d7 = { e2 bf [2] 96 a7 [2] d1 a5 [2] 96 b4 [2] d8 b8 [2] d4 b2 [2] c3 b9 [2] d8 f7 [2] e5 }

  condition:
    any of them
}