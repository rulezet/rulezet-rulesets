rule TTP_XOR_QUAD_CurrentVersionRun_4a9b {
  strings:
    $key_4a9b = { 19 f4 [2] 3d fa [2] 16 d6 [2] 38 f4 [2] 2c ef [2] 23 f5 [2] 3d e8 [2] 3f e9 [2] 24 ef [2] 38 e8 [2] 24 c7 }

  condition:
    any of them
}