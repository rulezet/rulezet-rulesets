rule TTP_XOR_QUAD_CurrentVersionRun_5ec4 {
  strings:
    $key_5ec4 = { 0d ab [2] 29 a5 [2] 02 89 [2] 2c ab [2] 38 b0 [2] 37 aa [2] 29 b7 [2] 2b b6 [2] 30 b0 [2] 2c b7 [2] 30 98 }

  condition:
    any of them
}