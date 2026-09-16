rule TTP_XOR_QUAD_CurrentVersionRun_45c7 {
  strings:
    $key_45c7 = { 16 a8 [2] 32 a6 [2] 19 8a [2] 37 a8 [2] 23 b3 [2] 2c a9 [2] 32 b4 [2] 30 b5 [2] 2b b3 [2] 37 b4 [2] 2b 9b }

  condition:
    any of them
}