rule TTP_XOR_QUAD_CurrentVersionRun_02d8 {
  strings:
    $key_02d8 = { 51 b7 [2] 75 b9 [2] 5e 95 [2] 70 b7 [2] 64 ac [2] 6b b6 [2] 75 ab [2] 77 aa [2] 6c ac [2] 70 ab [2] 6c 84 }

  condition:
    any of them
}