rule TTP_XOR_QUAD_CurrentVersionRun_48b5 {
  strings:
    $key_48b5 = { 1b da [2] 3f d4 [2] 14 f8 [2] 3a da [2] 2e c1 [2] 21 db [2] 3f c6 [2] 3d c7 [2] 26 c1 [2] 3a c6 [2] 26 e9 }

  condition:
    any of them
}