rule TTP_XOR_QUAD_CurrentVersionRun_5a86 {
  strings:
    $key_5a86 = { 09 e9 [2] 2d e7 [2] 06 cb [2] 28 e9 [2] 3c f2 [2] 33 e8 [2] 2d f5 [2] 2f f4 [2] 34 f2 [2] 28 f5 [2] 34 da }

  condition:
    any of them
}