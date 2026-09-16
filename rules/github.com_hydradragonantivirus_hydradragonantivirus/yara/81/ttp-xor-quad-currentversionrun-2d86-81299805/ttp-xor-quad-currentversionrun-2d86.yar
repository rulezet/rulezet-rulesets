rule TTP_XOR_QUAD_CurrentVersionRun_2d86 {
  strings:
    $key_2d86 = { 7e e9 [2] 5a e7 [2] 71 cb [2] 5f e9 [2] 4b f2 [2] 44 e8 [2] 5a f5 [2] 58 f4 [2] 43 f2 [2] 5f f5 [2] 43 da }

  condition:
    any of them
}