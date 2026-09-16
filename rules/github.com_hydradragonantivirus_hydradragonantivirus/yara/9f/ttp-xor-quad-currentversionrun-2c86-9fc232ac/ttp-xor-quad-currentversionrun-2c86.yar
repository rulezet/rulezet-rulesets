rule TTP_XOR_QUAD_CurrentVersionRun_2c86 {
  strings:
    $key_2c86 = { 7f e9 [2] 5b e7 [2] 70 cb [2] 5e e9 [2] 4a f2 [2] 45 e8 [2] 5b f5 [2] 59 f4 [2] 42 f2 [2] 5e f5 [2] 42 da }

  condition:
    any of them
}