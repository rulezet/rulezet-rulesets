rule TTP_XOR_QUAD_CurrentVersionRun_49a4 {
  strings:
    $key_49a4 = { 1a cb [2] 3e c5 [2] 15 e9 [2] 3b cb [2] 2f d0 [2] 20 ca [2] 3e d7 [2] 3c d6 [2] 27 d0 [2] 3b d7 [2] 27 f8 }

  condition:
    any of them
}