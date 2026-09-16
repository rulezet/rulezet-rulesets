rule TTP_XOR_QUAD_CurrentVersionRun_17d1 {
  strings:
    $key_17d1 = { 44 be [2] 60 b0 [2] 4b 9c [2] 65 be [2] 71 a5 [2] 7e bf [2] 60 a2 [2] 62 a3 [2] 79 a5 [2] 65 a2 [2] 79 8d }

  condition:
    any of them
}