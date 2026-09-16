rule TTP_XOR_MULT_DOSStub_17d2 {
  strings:
    $key_17d2 = { 43 ba [2] 37 a2 [2] 70 a0 [2] 37 b1 [2] 79 bd [2] 75 b7 [2] 62 bc [2] 79 f2 [2] 44 }

  condition:
    any of them
}