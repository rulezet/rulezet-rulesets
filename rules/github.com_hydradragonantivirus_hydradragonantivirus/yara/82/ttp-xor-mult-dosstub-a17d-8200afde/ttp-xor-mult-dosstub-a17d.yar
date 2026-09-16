rule TTP_XOR_MULT_DOSStub_a17d {
  strings:
    $key_a17d = { f5 15 [2] 81 0d [2] c6 0f [2] 81 1e [2] cf 12 [2] c3 18 [2] d4 13 [2] cf 5d [2] f2 }

  condition:
    any of them
}