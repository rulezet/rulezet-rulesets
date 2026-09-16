rule TTP_XOR_MULT_DOSStub_6cd7 {
  strings:
    $key_6cd7 = { 38 bf [2] 4c a7 [2] 0b a5 [2] 4c b4 [2] 02 b8 [2] 0e b2 [2] 19 b9 [2] 02 f7 [2] 3f }

  condition:
    any of them
}