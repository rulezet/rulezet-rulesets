rule TTP_XOR_QUAD_CurrentVersionRun_42d7 {
  strings:
    $key_42d7 = { 11 b8 [2] 35 b6 [2] 1e 9a [2] 30 b8 [2] 24 a3 [2] 2b b9 [2] 35 a4 [2] 37 a5 [2] 2c a3 [2] 30 a4 [2] 2c 8b }

  condition:
    any of them
}