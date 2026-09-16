rule TTP_XOR_QUAD_CurrentVersionRun_26d8 {
  strings:
    $key_26d8 = { 75 b7 [2] 51 b9 [2] 7a 95 [2] 54 b7 [2] 40 ac [2] 4f b6 [2] 51 ab [2] 53 aa [2] 48 ac [2] 54 ab [2] 48 84 }

  condition:
    any of them
}