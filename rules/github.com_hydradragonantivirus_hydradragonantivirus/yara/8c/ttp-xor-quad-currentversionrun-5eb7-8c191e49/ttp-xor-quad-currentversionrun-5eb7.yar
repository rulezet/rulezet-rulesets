rule TTP_XOR_QUAD_CurrentVersionRun_5eb7 {
  strings:
    $key_5eb7 = { 0d d8 [2] 29 d6 [2] 02 fa [2] 2c d8 [2] 38 c3 [2] 37 d9 [2] 29 c4 [2] 2b c5 [2] 30 c3 [2] 2c c4 [2] 30 eb }

  condition:
    any of them
}