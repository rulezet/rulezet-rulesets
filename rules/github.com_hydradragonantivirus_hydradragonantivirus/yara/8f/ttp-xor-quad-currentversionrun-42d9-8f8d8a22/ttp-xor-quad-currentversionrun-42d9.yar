rule TTP_XOR_QUAD_CurrentVersionRun_42d9 {
  strings:
    $key_42d9 = { 11 b6 [2] 35 b8 [2] 1e 94 [2] 30 b6 [2] 24 ad [2] 2b b7 [2] 35 aa [2] 37 ab [2] 2c ad [2] 30 aa [2] 2c 85 }

  condition:
    any of them
}