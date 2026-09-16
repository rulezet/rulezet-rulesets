rule TTP_XOR_QUAD_CurrentVersionRun_42b5 {
  strings:
    $key_42b5 = { 11 da [2] 35 d4 [2] 1e f8 [2] 30 da [2] 24 c1 [2] 2b db [2] 35 c6 [2] 37 c7 [2] 2c c1 [2] 30 c6 [2] 2c e9 }

  condition:
    any of them
}