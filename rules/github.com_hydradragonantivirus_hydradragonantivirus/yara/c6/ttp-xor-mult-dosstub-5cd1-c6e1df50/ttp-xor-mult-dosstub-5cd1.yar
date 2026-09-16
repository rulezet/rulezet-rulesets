rule TTP_XOR_MULT_DOSStub_5cd1 {
  strings:
    $key_5cd1 = { 08 b9 [2] 7c a1 [2] 3b a3 [2] 7c b2 [2] 32 be [2] 3e b4 [2] 29 bf [2] 32 f1 [2] 0f }

  condition:
    any of them
}