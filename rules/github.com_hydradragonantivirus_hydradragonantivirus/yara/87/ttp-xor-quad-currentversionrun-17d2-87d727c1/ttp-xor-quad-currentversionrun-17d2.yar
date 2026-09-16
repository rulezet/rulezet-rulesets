rule TTP_XOR_QUAD_CurrentVersionRun_17d2 {
  strings:
    $key_17d2 = { 44 bd [2] 60 b3 [2] 4b 9f [2] 65 bd [2] 71 a6 [2] 7e bc [2] 60 a1 [2] 62 a0 [2] 79 a6 [2] 65 a1 [2] 79 8e }

  condition:
    any of them
}