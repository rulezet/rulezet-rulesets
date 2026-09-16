rule TTP_XOR_QUAD_CurrentVersionRun_ead8 {
  strings:
    $key_ead8 = { b9 b7 [2] 9d b9 [2] b6 95 [2] 98 b7 [2] 8c ac [2] 83 b6 [2] 9d ab [2] 9f aa [2] 84 ac [2] 98 ab [2] 84 84 }

  condition:
    any of them
}