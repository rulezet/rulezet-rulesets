rule TTP_XOR_QUAD_CurrentVersionRun_3a86 {
  strings:
    $key_3a86 = { 69 e9 [2] 4d e7 [2] 66 cb [2] 48 e9 [2] 5c f2 [2] 53 e8 [2] 4d f5 [2] 4f f4 [2] 54 f2 [2] 48 f5 [2] 54 da }

  condition:
    any of them
}