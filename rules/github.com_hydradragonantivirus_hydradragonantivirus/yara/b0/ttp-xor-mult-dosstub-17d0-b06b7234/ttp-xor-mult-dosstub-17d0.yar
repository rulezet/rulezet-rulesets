rule TTP_XOR_MULT_DOSStub_17d0 {
  strings:
    $key_17d0 = { 43 b8 [2] 37 a0 [2] 70 a2 [2] 37 b3 [2] 79 bf [2] 75 b5 [2] 62 be [2] 79 f0 [2] 44 }

  condition:
    any of them
}