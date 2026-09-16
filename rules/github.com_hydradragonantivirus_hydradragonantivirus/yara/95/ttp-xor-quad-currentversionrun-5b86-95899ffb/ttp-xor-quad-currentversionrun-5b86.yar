rule TTP_XOR_QUAD_CurrentVersionRun_5b86 {
  strings:
    $key_5b86 = { 08 e9 [2] 2c e7 [2] 07 cb [2] 29 e9 [2] 3d f2 [2] 32 e8 [2] 2c f5 [2] 2e f4 [2] 35 f2 [2] 29 f5 [2] 35 da }

  condition:
    any of them
}