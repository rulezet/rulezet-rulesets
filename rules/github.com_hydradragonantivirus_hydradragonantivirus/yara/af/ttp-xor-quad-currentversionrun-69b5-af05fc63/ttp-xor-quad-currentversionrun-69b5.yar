rule TTP_XOR_QUAD_CurrentVersionRun_69b5 {
  strings:
    $key_69b5 = { 3a da [2] 1e d4 [2] 35 f8 [2] 1b da [2] 0f c1 [2] 00 db [2] 1e c6 [2] 1c c7 [2] 07 c1 [2] 1b c6 [2] 07 e9 }

  condition:
    any of them
}