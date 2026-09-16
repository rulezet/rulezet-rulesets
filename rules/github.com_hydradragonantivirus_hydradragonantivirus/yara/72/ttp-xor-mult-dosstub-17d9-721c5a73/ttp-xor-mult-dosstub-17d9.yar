rule TTP_XOR_MULT_DOSStub_17d9 {
  strings:
    $key_17d9 = { 43 b1 [2] 37 a9 [2] 70 ab [2] 37 ba [2] 79 b6 [2] 75 bc [2] 62 b7 [2] 79 f9 [2] 44 }

  condition:
    any of them
}