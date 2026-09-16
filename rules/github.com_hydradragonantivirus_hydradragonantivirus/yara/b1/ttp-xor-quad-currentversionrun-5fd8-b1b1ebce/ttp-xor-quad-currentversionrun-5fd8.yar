rule TTP_XOR_QUAD_CurrentVersionRun_5fd8 {
  strings:
    $key_5fd8 = { 0c b7 [2] 28 b9 [2] 03 95 [2] 2d b7 [2] 39 ac [2] 36 b6 [2] 28 ab [2] 2a aa [2] 31 ac [2] 2d ab [2] 31 84 }

  condition:
    any of them
}