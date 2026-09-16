rule TTP_XOR_QUAD_CurrentVersionRun_4b86 {
  strings:
    $key_4b86 = { 18 e9 [2] 3c e7 [2] 17 cb [2] 39 e9 [2] 2d f2 [2] 22 e8 [2] 3c f5 [2] 3e f4 [2] 25 f2 [2] 39 f5 [2] 25 da }

  condition:
    any of them
}