rule TTP_XOR_QUAD_CurrentVersionRun_4e86 {
  strings:
    $key_4e86 = { 1d e9 [2] 39 e7 [2] 12 cb [2] 3c e9 [2] 28 f2 [2] 27 e8 [2] 39 f5 [2] 3b f4 [2] 20 f2 [2] 3c f5 [2] 20 da }

  condition:
    any of them
}