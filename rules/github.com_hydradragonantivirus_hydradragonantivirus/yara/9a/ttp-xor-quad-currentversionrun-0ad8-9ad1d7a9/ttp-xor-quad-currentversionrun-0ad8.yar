rule TTP_XOR_QUAD_CurrentVersionRun_0ad8 {
  strings:
    $key_0ad8 = { 59 b7 [2] 7d b9 [2] 56 95 [2] 78 b7 [2] 6c ac [2] 63 b6 [2] 7d ab [2] 7f aa [2] 64 ac [2] 78 ab [2] 64 84 }

  condition:
    any of them
}