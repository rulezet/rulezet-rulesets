rule TTP_XOR_QUAD_CurrentVersionRun_76d8 {
  strings:
    $key_76d8 = { 25 b7 [2] 01 b9 [2] 2a 95 [2] 04 b7 [2] 10 ac [2] 1f b6 [2] 01 ab [2] 03 aa [2] 18 ac [2] 04 ab [2] 18 84 }

  condition:
    any of them
}