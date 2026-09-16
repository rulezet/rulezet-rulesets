rule TTP_XOR_QUAD_CurrentVersionRun_7d86 {
  strings:
    $key_7d86 = { 2e e9 [2] 0a e7 [2] 21 cb [2] 0f e9 [2] 1b f2 [2] 14 e8 [2] 0a f5 [2] 08 f4 [2] 13 f2 [2] 0f f5 [2] 13 da }

  condition:
    any of them
}