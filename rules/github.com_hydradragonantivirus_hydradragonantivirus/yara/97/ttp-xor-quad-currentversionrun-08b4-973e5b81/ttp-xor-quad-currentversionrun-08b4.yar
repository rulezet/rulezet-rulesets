rule TTP_XOR_QUAD_CurrentVersionRun_08b4 {
  strings:
    $key_08b4 = { 5b db [2] 7f d5 [2] 54 f9 [2] 7a db [2] 6e c0 [2] 61 da [2] 7f c7 [2] 7d c6 [2] 66 c0 [2] 7a c7 [2] 66 e8 }

  condition:
    any of them
}