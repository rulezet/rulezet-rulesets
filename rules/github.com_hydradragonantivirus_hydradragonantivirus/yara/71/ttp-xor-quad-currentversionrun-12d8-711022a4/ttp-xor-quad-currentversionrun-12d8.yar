rule TTP_XOR_QUAD_CurrentVersionRun_12d8 {
  strings:
    $key_12d8 = { 41 b7 [2] 65 b9 [2] 4e 95 [2] 60 b7 [2] 74 ac [2] 7b b6 [2] 65 ab [2] 67 aa [2] 7c ac [2] 60 ab [2] 7c 84 }

  condition:
    any of them
}