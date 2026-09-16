rule TTP_XOR_QUAD_CurrentVersionRun_5ad8 {
  strings:
    $key_5ad8 = { 09 b7 [2] 2d b9 [2] 06 95 [2] 28 b7 [2] 3c ac [2] 33 b6 [2] 2d ab [2] 2f aa [2] 34 ac [2] 28 ab [2] 34 84 }

  condition:
    any of them
}