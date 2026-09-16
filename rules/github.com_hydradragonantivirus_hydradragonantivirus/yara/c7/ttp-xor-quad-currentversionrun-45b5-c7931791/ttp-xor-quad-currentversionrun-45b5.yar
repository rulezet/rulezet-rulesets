rule TTP_XOR_QUAD_CurrentVersionRun_45b5 {
  strings:
    $key_45b5 = { 16 da [2] 32 d4 [2] 19 f8 [2] 37 da [2] 23 c1 [2] 2c db [2] 32 c6 [2] 30 c7 [2] 2b c1 [2] 37 c6 [2] 2b e9 }

  condition:
    any of them
}