rule TTP_XOR_QUAD_CurrentVersionRun_2a86 {
  strings:
    $key_2a86 = { 79 e9 [2] 5d e7 [2] 76 cb [2] 58 e9 [2] 4c f2 [2] 43 e8 [2] 5d f5 [2] 5f f4 [2] 44 f2 [2] 58 f5 [2] 44 da }

  condition:
    any of them
}