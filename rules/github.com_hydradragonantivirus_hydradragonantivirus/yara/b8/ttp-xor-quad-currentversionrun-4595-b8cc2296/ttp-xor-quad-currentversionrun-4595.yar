rule TTP_XOR_QUAD_CurrentVersionRun_4595 {
  strings:
    $key_4595 = { 16 fa [2] 32 f4 [2] 19 d8 [2] 37 fa [2] 23 e1 [2] 2c fb [2] 32 e6 [2] 30 e7 [2] 2b e1 [2] 37 e6 [2] 2b c9 }

  condition:
    any of them
}