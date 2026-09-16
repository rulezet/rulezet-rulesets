rule TTP_XOR_QUAD_CurrentVersionRun_28b4 {
  strings:
    $key_28b4 = { 7b db [2] 5f d5 [2] 74 f9 [2] 5a db [2] 4e c0 [2] 41 da [2] 5f c7 [2] 5d c6 [2] 46 c0 [2] 5a c7 [2] 46 e8 }

  condition:
    any of them
}