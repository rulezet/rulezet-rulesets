rule TTP_XOR_QUAD_CurrentVersionRun_3cb8 {
  strings:
    $key_3cb8 = { 6f d7 [2] 4b d9 [2] 60 f5 [2] 4e d7 [2] 5a cc [2] 55 d6 [2] 4b cb [2] 49 ca [2] 52 cc [2] 4e cb [2] 52 e4 }

  condition:
    any of them
}