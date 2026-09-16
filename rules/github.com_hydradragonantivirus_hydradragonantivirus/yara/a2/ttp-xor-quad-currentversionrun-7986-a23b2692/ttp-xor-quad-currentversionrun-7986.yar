rule TTP_XOR_QUAD_CurrentVersionRun_7986 {
  strings:
    $key_7986 = { 2a e9 [2] 0e e7 [2] 25 cb [2] 0b e9 [2] 1f f2 [2] 10 e8 [2] 0e f5 [2] 0c f4 [2] 17 f2 [2] 0b f5 [2] 17 da }

  condition:
    any of them
}