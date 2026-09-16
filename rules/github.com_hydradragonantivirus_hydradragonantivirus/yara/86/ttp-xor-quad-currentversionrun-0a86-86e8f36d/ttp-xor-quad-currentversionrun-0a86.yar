rule TTP_XOR_QUAD_CurrentVersionRun_0a86 {
  strings:
    $key_0a86 = { 59 e9 [2] 7d e7 [2] 56 cb [2] 78 e9 [2] 6c f2 [2] 63 e8 [2] 7d f5 [2] 7f f4 [2] 64 f2 [2] 78 f5 [2] 64 da }

  condition:
    any of them
}