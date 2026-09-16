rule TTP_XOR_QUAD_CurrentVersionRun_6cb8 {
  strings:
    $key_6cb8 = { 3f d7 [2] 1b d9 [2] 30 f5 [2] 1e d7 [2] 0a cc [2] 05 d6 [2] 1b cb [2] 19 ca [2] 02 cc [2] 1e cb [2] 02 e4 }

  condition:
    any of them
}