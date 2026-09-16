rule TTP_XOR_QUAD_CurrentVersionRun_7fd8 {
  strings:
    $key_7fd8 = { 2c b7 [2] 08 b9 [2] 23 95 [2] 0d b7 [2] 19 ac [2] 16 b6 [2] 08 ab [2] 0a aa [2] 11 ac [2] 0d ab [2] 11 84 }

  condition:
    any of them
}