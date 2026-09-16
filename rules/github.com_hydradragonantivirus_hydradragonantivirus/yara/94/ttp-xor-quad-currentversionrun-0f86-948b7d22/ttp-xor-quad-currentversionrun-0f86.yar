rule TTP_XOR_QUAD_CurrentVersionRun_0f86 {
  strings:
    $key_0f86 = { 5c e9 [2] 78 e7 [2] 53 cb [2] 7d e9 [2] 69 f2 [2] 66 e8 [2] 78 f5 [2] 7a f4 [2] 61 f2 [2] 7d f5 [2] 61 da }

  condition:
    any of them
}