rule TTP_XOR_MULT_DOSStub_17d1 {
  strings:
    $key_17d1 = { 43 b9 [2] 37 a1 [2] 70 a3 [2] 37 b2 [2] 79 be [2] 75 b4 [2] 62 bf [2] 79 f1 [2] 44 }

  condition:
    any of them
}