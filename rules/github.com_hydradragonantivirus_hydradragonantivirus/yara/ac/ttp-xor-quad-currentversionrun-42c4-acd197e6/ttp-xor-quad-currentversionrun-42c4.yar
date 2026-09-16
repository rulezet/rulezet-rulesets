rule TTP_XOR_QUAD_CurrentVersionRun_42c4 {
  strings:
    $key_42c4 = { 11 ab [2] 35 a5 [2] 1e 89 [2] 30 ab [2] 24 b0 [2] 2b aa [2] 35 b7 [2] 37 b6 [2] 2c b0 [2] 30 b7 [2] 2c 98 }

  condition:
    any of them
}