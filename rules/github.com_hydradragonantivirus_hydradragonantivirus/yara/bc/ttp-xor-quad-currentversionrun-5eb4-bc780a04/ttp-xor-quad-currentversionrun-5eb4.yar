rule TTP_XOR_QUAD_CurrentVersionRun_5eb4 {
  strings:
    $key_5eb4 = { 0d db [2] 29 d5 [2] 02 f9 [2] 2c db [2] 38 c0 [2] 37 da [2] 29 c7 [2] 2b c6 [2] 30 c0 [2] 2c c7 [2] 30 e8 }

  condition:
    any of them
}