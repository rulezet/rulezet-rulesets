rule TTP_XOR_QUAD_CurrentVersionRun_45c4 {
  strings:
    $key_45c4 = { 16 ab [2] 32 a5 [2] 19 89 [2] 37 ab [2] 23 b0 [2] 2c aa [2] 32 b7 [2] 30 b6 [2] 2b b0 [2] 37 b7 [2] 2b 98 }

  condition:
    any of them
}