rule TTP_XOR_QUAD_CurrentVersionRun_32d8 {
  strings:
    $key_32d8 = { 61 b7 [2] 45 b9 [2] 6e 95 [2] 40 b7 [2] 54 ac [2] 5b b6 [2] 45 ab [2] 47 aa [2] 5c ac [2] 40 ab [2] 5c 84 }

  condition:
    any of them
}