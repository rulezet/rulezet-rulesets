rule TTP_XOR_MULT_DOSStub_17d7 {
  strings:
    $key_17d7 = { 43 bf [2] 37 a7 [2] 70 a5 [2] 37 b4 [2] 79 b8 [2] 75 b2 [2] 62 b9 [2] 79 f7 [2] 44 }

  condition:
    any of them
}