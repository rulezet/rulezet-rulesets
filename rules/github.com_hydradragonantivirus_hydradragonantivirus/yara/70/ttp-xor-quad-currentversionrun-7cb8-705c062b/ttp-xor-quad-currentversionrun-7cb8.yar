rule TTP_XOR_QUAD_CurrentVersionRun_7cb8 {
  strings:
    $key_7cb8 = { 2f d7 [2] 0b d9 [2] 20 f5 [2] 0e d7 [2] 1a cc [2] 15 d6 [2] 0b cb [2] 09 ca [2] 12 cc [2] 0e cb [2] 12 e4 }

  condition:
    any of them
}