rule TTP_XOR_QUAD_CurrentVersionRun_7bd8 {
  strings:
    $key_7bd8 = { 28 b7 [2] 0c b9 [2] 27 95 [2] 09 b7 [2] 1d ac [2] 12 b6 [2] 0c ab [2] 0e aa [2] 15 ac [2] 09 ab [2] 15 84 }

  condition:
    any of them
}