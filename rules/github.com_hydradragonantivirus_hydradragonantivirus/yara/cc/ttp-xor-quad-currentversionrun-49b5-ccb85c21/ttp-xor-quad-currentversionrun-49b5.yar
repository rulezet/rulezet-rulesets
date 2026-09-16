rule TTP_XOR_QUAD_CurrentVersionRun_49b5 {
  strings:
    $key_49b5 = { 1a da [2] 3e d4 [2] 15 f8 [2] 3b da [2] 2f c1 [2] 20 db [2] 3e c6 [2] 3c c7 [2] 27 c1 [2] 3b c6 [2] 27 e9 }

  condition:
    any of them
}