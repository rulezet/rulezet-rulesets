rule TTP_XOR_QUAD_CurrentVersionRun_4f86 {
  strings:
    $key_4f86 = { 1c e9 [2] 38 e7 [2] 13 cb [2] 3d e9 [2] 29 f2 [2] 26 e8 [2] 38 f5 [2] 3a f4 [2] 21 f2 [2] 3d f5 [2] 21 da }

  condition:
    any of them
}