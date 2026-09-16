rule TTP_XOR_QUAD_CurrentVersionRun_7ed8 {
  strings:
    $key_7ed8 = { 2d b7 [2] 09 b9 [2] 22 95 [2] 0c b7 [2] 18 ac [2] 17 b6 [2] 09 ab [2] 0b aa [2] 10 ac [2] 0c ab [2] 10 84 }

  condition:
    any of them
}