rule TTP_XOR_MULT_DOSStub_1cd1 {
  strings:
    $key_1cd1 = { 48 b9 [2] 3c a1 [2] 7b a3 [2] 3c b2 [2] 72 be [2] 7e b4 [2] 69 bf [2] 72 f1 [2] 4f }

  condition:
    any of them
}