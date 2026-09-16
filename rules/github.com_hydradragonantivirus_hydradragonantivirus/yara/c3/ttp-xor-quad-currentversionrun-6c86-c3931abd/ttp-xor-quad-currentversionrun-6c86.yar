rule TTP_XOR_QUAD_CurrentVersionRun_6c86 {
  strings:
    $key_6c86 = { 3f e9 [2] 1b e7 [2] 30 cb [2] 1e e9 [2] 0a f2 [2] 05 e8 [2] 1b f5 [2] 19 f4 [2] 02 f2 [2] 1e f5 [2] 02 da }

  condition:
    any of them
}