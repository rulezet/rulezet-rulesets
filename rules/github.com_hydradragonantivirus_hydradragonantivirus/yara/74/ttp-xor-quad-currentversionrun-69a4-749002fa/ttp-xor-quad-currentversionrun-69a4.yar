rule TTP_XOR_QUAD_CurrentVersionRun_69a4 {
  strings:
    $key_69a4 = { 3a cb [2] 1e c5 [2] 35 e9 [2] 1b cb [2] 0f d0 [2] 00 ca [2] 1e d7 [2] 1c d6 [2] 07 d0 [2] 1b d7 [2] 07 f8 }

  condition:
    any of them
}