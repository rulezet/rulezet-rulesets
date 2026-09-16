rule TTP_XOR_QUAD_CurrentVersionRun_2bd8 {
  strings:
    $key_2bd8 = { 78 b7 [2] 5c b9 [2] 77 95 [2] 59 b7 [2] 4d ac [2] 42 b6 [2] 5c ab [2] 5e aa [2] 45 ac [2] 59 ab [2] 45 84 }

  condition:
    any of them
}