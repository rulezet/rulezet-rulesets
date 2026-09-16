rule TTP_XOR_MULT_DOSStub_17d4 {
  strings:
    $key_17d4 = { 43 bc [2] 37 a4 [2] 70 a6 [2] 37 b7 [2] 79 bb [2] 75 b1 [2] 62 ba [2] 79 f4 [2] 44 }

  condition:
    any of them
}