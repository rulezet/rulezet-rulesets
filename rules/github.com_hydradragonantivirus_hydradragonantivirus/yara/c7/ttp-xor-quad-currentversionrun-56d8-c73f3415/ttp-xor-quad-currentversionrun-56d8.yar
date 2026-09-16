rule TTP_XOR_QUAD_CurrentVersionRun_56d8 {
  strings:
    $key_56d8 = { 05 b7 [2] 21 b9 [2] 0a 95 [2] 24 b7 [2] 30 ac [2] 3f b6 [2] 21 ab [2] 23 aa [2] 38 ac [2] 24 ab [2] 38 84 }

  condition:
    any of them
}