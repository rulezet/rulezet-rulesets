rule TTP_XOR_QUAD_CurrentVersionRun_4bd8 {
  strings:
    $key_4bd8 = { 18 b7 [2] 3c b9 [2] 17 95 [2] 39 b7 [2] 2d ac [2] 22 b6 [2] 3c ab [2] 3e aa [2] 25 ac [2] 39 ab [2] 25 84 }

  condition:
    any of them
}