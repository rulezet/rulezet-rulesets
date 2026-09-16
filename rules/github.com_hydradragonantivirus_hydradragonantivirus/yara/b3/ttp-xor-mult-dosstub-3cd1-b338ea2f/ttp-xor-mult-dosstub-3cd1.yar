rule TTP_XOR_MULT_DOSStub_3cd1 {
  strings:
    $key_3cd1 = { 68 b9 [2] 1c a1 [2] 5b a3 [2] 1c b2 [2] 52 be [2] 5e b4 [2] 49 bf [2] 52 f1 [2] 6f }

  condition:
    any of them
}