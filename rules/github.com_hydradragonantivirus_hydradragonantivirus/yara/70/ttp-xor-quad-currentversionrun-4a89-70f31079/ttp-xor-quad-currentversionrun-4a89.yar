rule TTP_XOR_QUAD_CurrentVersionRun_4a89 {
  strings:
    $key_4a89 = { 19 e6 [2] 3d e8 [2] 16 c4 [2] 38 e6 [2] 2c fd [2] 23 e7 [2] 3d fa [2] 3f fb [2] 24 fd [2] 38 fa [2] 24 d5 }

  condition:
    any of them
}