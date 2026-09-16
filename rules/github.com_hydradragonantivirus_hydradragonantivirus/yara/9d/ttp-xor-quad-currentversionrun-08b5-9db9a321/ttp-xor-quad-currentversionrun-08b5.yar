rule TTP_XOR_QUAD_CurrentVersionRun_08b5 {
  strings:
    $key_08b5 = { 5b da [2] 7f d4 [2] 54 f8 [2] 7a da [2] 6e c1 [2] 61 db [2] 7f c6 [2] 7d c7 [2] 66 c1 [2] 7a c6 [2] 66 e9 }

  condition:
    any of them
}