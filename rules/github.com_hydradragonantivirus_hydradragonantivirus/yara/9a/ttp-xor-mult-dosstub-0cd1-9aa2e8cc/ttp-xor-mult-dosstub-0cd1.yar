rule TTP_XOR_MULT_DOSStub_0cd1 {
  strings:
    $key_0cd1 = { 58 b9 [2] 2c a1 [2] 6b a3 [2] 2c b2 [2] 62 be [2] 6e b4 [2] 79 bf [2] 62 f1 [2] 5f }

  condition:
    any of them
}