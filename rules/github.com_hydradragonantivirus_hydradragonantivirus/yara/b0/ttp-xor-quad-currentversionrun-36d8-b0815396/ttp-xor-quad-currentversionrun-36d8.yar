rule TTP_XOR_QUAD_CurrentVersionRun_36d8 {
  strings:
    $key_36d8 = { 65 b7 [2] 41 b9 [2] 6a 95 [2] 44 b7 [2] 50 ac [2] 5f b6 [2] 41 ab [2] 43 aa [2] 58 ac [2] 44 ab [2] 58 84 }

  condition:
    any of them
}