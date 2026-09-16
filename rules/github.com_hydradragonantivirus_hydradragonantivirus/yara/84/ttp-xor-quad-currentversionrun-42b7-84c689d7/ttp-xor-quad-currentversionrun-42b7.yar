rule TTP_XOR_QUAD_CurrentVersionRun_42b7 {
  strings:
    $key_42b7 = { 11 d8 [2] 35 d6 [2] 1e fa [2] 30 d8 [2] 24 c3 [2] 2b d9 [2] 35 c4 [2] 37 c5 [2] 2c c3 [2] 30 c4 [2] 2c eb }

  condition:
    any of them
}