rule TTP_XOR_QUAD_CurrentVersionRun_45b7 {
  strings:
    $key_45b7 = { 16 d8 [2] 32 d6 [2] 19 fa [2] 37 d8 [2] 23 c3 [2] 2c d9 [2] 32 c4 [2] 30 c5 [2] 2b c3 [2] 37 c4 [2] 2b eb }

  condition:
    any of them
}