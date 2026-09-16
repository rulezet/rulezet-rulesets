rule TTP_XOR_MULT_DOSStub_1cd7 {
  strings:
    $key_1cd7 = { 48 bf [2] 3c a7 [2] 7b a5 [2] 3c b4 [2] 72 b8 [2] 7e b2 [2] 69 b9 [2] 72 f7 [2] 4f }

  condition:
    any of them
}