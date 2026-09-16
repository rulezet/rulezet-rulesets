rule TTP_XOR_QUAD_CurrentVersionRun_5bd8 {
  strings:
    $key_5bd8 = { 08 b7 [2] 2c b9 [2] 07 95 [2] 29 b7 [2] 3d ac [2] 32 b6 [2] 2c ab [2] 2e aa [2] 35 ac [2] 29 ab [2] 35 84 }

  condition:
    any of them
}