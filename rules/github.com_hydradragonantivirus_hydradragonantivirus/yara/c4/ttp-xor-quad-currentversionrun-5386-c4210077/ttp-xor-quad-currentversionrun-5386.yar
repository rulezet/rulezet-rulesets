rule TTP_XOR_QUAD_CurrentVersionRun_5386 {
  strings:
    $key_5386 = { 00 e9 [2] 24 e7 [2] 0f cb [2] 21 e9 [2] 35 f2 [2] 3a e8 [2] 24 f5 [2] 26 f4 [2] 3d f2 [2] 21 f5 [2] 3d da }

  condition:
    any of them
}