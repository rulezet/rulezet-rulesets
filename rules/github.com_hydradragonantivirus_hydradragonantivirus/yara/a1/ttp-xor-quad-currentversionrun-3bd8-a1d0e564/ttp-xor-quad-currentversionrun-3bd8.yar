rule TTP_XOR_QUAD_CurrentVersionRun_3bd8 {
  strings:
    $key_3bd8 = { 68 b7 [2] 4c b9 [2] 67 95 [2] 49 b7 [2] 5d ac [2] 52 b6 [2] 4c ab [2] 4e aa [2] 55 ac [2] 49 ab [2] 55 84 }

  condition:
    any of them
}