rule TTP_XOR_QUAD_CurrentVersionRun_45b4 {
  strings:
    $key_45b4 = { 16 db [2] 32 d5 [2] 19 f9 [2] 37 db [2] 23 c0 [2] 2c da [2] 32 c7 [2] 30 c6 [2] 2b c0 [2] 37 c7 [2] 2b e8 }

  condition:
    any of them
}