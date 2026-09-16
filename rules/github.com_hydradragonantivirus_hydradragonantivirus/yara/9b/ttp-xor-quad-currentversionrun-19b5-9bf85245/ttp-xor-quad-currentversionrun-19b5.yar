rule TTP_XOR_QUAD_CurrentVersionRun_19b5 {
  strings:
    $key_19b5 = { 4a da [2] 6e d4 [2] 45 f8 [2] 6b da [2] 7f c1 [2] 70 db [2] 6e c6 [2] 6c c7 [2] 77 c1 [2] 6b c6 [2] 77 e9 }

  condition:
    any of them
}