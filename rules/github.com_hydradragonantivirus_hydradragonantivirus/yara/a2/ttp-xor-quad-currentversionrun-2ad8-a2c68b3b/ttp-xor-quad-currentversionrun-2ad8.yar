rule TTP_XOR_QUAD_CurrentVersionRun_2ad8 {
  strings:
    $key_2ad8 = { 79 b7 [2] 5d b9 [2] 76 95 [2] 58 b7 [2] 4c ac [2] 43 b6 [2] 5d ab [2] 5f aa [2] 44 ac [2] 58 ab [2] 44 84 }

  condition:
    any of them
}