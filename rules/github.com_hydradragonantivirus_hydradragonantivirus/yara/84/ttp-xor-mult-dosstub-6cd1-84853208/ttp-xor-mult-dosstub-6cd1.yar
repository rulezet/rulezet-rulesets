rule TTP_XOR_MULT_DOSStub_6cd1 {
  strings:
    $key_6cd1 = { 38 b9 [2] 4c a1 [2] 0b a3 [2] 4c b2 [2] 02 be [2] 0e b4 [2] 19 bf [2] 02 f1 [2] 3f }

  condition:
    any of them
}