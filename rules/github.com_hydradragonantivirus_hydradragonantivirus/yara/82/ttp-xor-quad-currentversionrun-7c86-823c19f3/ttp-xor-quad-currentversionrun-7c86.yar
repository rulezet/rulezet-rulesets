rule TTP_XOR_QUAD_CurrentVersionRun_7c86 {
  strings:
    $key_7c86 = { 2f e9 [2] 0b e7 [2] 20 cb [2] 0e e9 [2] 1a f2 [2] 15 e8 [2] 0b f5 [2] 09 f4 [2] 12 f2 [2] 0e f5 [2] 12 da }

  condition:
    any of them
}