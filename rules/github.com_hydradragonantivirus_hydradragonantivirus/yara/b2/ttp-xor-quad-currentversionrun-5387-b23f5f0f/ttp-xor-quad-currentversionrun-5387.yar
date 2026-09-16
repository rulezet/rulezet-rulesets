rule TTP_XOR_QUAD_CurrentVersionRun_5387 {
  strings:
    $key_5387 = { 00 e8 [2] 24 e6 [2] 0f ca [2] 21 e8 [2] 35 f3 [2] 3a e9 [2] 24 f4 [2] 26 f5 [2] 3d f3 [2] 21 f4 [2] 3d db }

  condition:
    any of them
}