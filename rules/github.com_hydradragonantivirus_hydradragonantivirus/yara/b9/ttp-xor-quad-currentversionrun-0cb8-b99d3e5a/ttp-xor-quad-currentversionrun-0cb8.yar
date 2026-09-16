rule TTP_XOR_QUAD_CurrentVersionRun_0cb8 {
  strings:
    $key_0cb8 = { 5f d7 [2] 7b d9 [2] 50 f5 [2] 7e d7 [2] 6a cc [2] 65 d6 [2] 7b cb [2] 79 ca [2] 62 cc [2] 7e cb [2] 62 e4 }

  condition:
    any of them
}