rule TTP_XOR_QUAD_CurrentVersionRun_58b4 {
  strings:
    $key_58b4 = { 0b db [2] 2f d5 [2] 04 f9 [2] 2a db [2] 3e c0 [2] 31 da [2] 2f c7 [2] 2d c6 [2] 36 c0 [2] 2a c7 [2] 36 e8 }

  condition:
    any of them
}