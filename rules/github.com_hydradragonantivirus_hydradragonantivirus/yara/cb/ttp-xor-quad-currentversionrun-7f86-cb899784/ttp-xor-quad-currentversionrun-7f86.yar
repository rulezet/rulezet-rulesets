rule TTP_XOR_QUAD_CurrentVersionRun_7f86 {
  strings:
    $key_7f86 = { 2c e9 [2] 08 e7 [2] 23 cb [2] 0d e9 [2] 19 f2 [2] 16 e8 [2] 08 f5 [2] 0a f4 [2] 11 f2 [2] 0d f5 [2] 11 da }

  condition:
    any of them
}