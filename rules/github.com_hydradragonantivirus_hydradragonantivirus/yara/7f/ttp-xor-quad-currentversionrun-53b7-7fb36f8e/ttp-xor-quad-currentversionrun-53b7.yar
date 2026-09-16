rule TTP_XOR_QUAD_CurrentVersionRun_53b7 {
  strings:
    $key_53b7 = { 00 d8 [2] 24 d6 [2] 0f fa [2] 21 d8 [2] 35 c3 [2] 3a d9 [2] 24 c4 [2] 26 c5 [2] 3d c3 [2] 21 c4 [2] 3d eb }

  condition:
    any of them
}