rule TTP_XOR_QUAD_CurrentVersionRun_17d7 {
  strings:
    $key_17d7 = { 44 b8 [2] 60 b6 [2] 4b 9a [2] 65 b8 [2] 71 a3 [2] 7e b9 [2] 60 a4 [2] 62 a5 [2] 79 a3 [2] 65 a4 [2] 79 8b }

  condition:
    any of them
}