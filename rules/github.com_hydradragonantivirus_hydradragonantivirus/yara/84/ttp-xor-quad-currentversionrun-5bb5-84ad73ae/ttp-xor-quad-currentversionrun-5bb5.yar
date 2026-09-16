rule TTP_XOR_QUAD_CurrentVersionRun_5bb5 {
  strings:
    $key_5bb5 = { 08 da [2] 2c d4 [2] 07 f8 [2] 29 da [2] 3d c1 [2] 32 db [2] 2c c6 [2] 2e c7 [2] 35 c1 [2] 29 c6 [2] 35 e9 }

  condition:
    any of them
}