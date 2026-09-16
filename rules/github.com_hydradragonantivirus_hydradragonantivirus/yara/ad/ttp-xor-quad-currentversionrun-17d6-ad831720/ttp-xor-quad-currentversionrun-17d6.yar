rule TTP_XOR_QUAD_CurrentVersionRun_17d6 {
  strings:
    $key_17d6 = { 44 b9 [2] 60 b7 [2] 4b 9b [2] 65 b9 [2] 71 a2 [2] 7e b8 [2] 60 a5 [2] 62 a4 [2] 79 a2 [2] 65 a5 [2] 79 8a }

  condition:
    any of them
}