rule TTP_XOR_QUAD_CurrentVersionRun_67d8 {
  strings:
    $key_67d8 = { 34 b7 [2] 10 b9 [2] 3b 95 [2] 15 b7 [2] 01 ac [2] 0e b6 [2] 10 ab [2] 12 aa [2] 09 ac [2] 15 ab [2] 09 84 }

  condition:
    any of them
}