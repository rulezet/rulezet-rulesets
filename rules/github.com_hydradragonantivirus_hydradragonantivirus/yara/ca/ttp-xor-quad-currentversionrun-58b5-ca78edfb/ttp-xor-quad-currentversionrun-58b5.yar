rule TTP_XOR_QUAD_CurrentVersionRun_58b5 {
  strings:
    $key_58b5 = { 0b da [2] 2f d4 [2] 04 f8 [2] 2a da [2] 3e c1 [2] 31 db [2] 2f c6 [2] 2d c7 [2] 36 c1 [2] 2a c6 [2] 36 e9 }

  condition:
    any of them
}