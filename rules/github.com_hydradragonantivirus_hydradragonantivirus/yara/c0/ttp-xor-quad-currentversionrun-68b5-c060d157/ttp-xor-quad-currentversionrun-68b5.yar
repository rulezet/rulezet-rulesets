rule TTP_XOR_QUAD_CurrentVersionRun_68b5 {
  strings:
    $key_68b5 = { 3b da [2] 1f d4 [2] 34 f8 [2] 1a da [2] 0e c1 [2] 01 db [2] 1f c6 [2] 1d c7 [2] 06 c1 [2] 1a c6 [2] 06 e9 }

  condition:
    any of them
}