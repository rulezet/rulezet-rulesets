rule TTP_XOR_QUAD_CurrentVersionRun_7086 {
  strings:
    $key_7086 = { 23 e9 [2] 07 e7 [2] 2c cb [2] 02 e9 [2] 16 f2 [2] 19 e8 [2] 07 f5 [2] 05 f4 [2] 1e f2 [2] 02 f5 [2] 1e da }

  condition:
    any of them
}