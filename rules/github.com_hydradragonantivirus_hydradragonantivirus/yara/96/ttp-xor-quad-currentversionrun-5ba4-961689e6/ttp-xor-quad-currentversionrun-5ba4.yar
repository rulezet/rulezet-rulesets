rule TTP_XOR_QUAD_CurrentVersionRun_5ba4 {
  strings:
    $key_5ba4 = { 08 cb [2] 2c c5 [2] 07 e9 [2] 29 cb [2] 3d d0 [2] 32 ca [2] 2c d7 [2] 2e d6 [2] 35 d0 [2] 29 d7 [2] 35 f8 }

  condition:
    any of them
}