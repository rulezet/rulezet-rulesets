rule TTP_XOR_QUAD_CurrentVersionRun_4086 {
  strings:
    $key_4086 = { 13 e9 [2] 37 e7 [2] 1c cb [2] 32 e9 [2] 26 f2 [2] 29 e8 [2] 37 f5 [2] 35 f4 [2] 2e f2 [2] 32 f5 [2] 2e da }

  condition:
    any of them
}