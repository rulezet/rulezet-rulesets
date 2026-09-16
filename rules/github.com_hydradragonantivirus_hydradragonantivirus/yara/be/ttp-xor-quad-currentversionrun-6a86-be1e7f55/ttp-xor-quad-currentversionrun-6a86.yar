rule TTP_XOR_QUAD_CurrentVersionRun_6a86 {
  strings:
    $key_6a86 = { 39 e9 [2] 1d e7 [2] 36 cb [2] 18 e9 [2] 0c f2 [2] 03 e8 [2] 1d f5 [2] 1f f4 [2] 04 f2 [2] 18 f5 [2] 04 da }

  condition:
    any of them
}