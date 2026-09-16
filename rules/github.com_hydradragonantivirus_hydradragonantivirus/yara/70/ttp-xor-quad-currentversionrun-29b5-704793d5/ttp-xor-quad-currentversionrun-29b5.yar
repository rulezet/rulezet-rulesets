rule TTP_XOR_QUAD_CurrentVersionRun_29b5 {
  strings:
    $key_29b5 = { 7a da [2] 5e d4 [2] 75 f8 [2] 5b da [2] 4f c1 [2] 40 db [2] 5e c6 [2] 5c c7 [2] 47 c1 [2] 5b c6 [2] 47 e9 }

  condition:
    any of them
}