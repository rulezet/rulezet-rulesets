rule TTP_XOR_QUAD_CurrentVersionRun_42c7 {
  strings:
    $key_42c7 = { 11 a8 [2] 35 a6 [2] 1e 8a [2] 30 a8 [2] 24 b3 [2] 2b a9 [2] 35 b4 [2] 37 b5 [2] 2c b3 [2] 30 b4 [2] 2c 9b }

  condition:
    any of them
}