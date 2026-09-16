rule TTP_XOR_QUAD_CurrentVersionRun_6fd8 {
  strings:
    $key_6fd8 = { 3c b7 [2] 18 b9 [2] 33 95 [2] 1d b7 [2] 09 ac [2] 06 b6 [2] 18 ab [2] 1a aa [2] 01 ac [2] 1d ab [2] 01 84 }

  condition:
    any of them
}