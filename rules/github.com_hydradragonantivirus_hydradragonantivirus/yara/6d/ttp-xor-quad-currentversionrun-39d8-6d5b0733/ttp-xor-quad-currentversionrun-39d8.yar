rule TTP_XOR_QUAD_CurrentVersionRun_39d8 {
  strings:
    $key_39d8 = { 6a b7 [2] 4e b9 [2] 65 95 [2] 4b b7 [2] 5f ac [2] 50 b6 [2] 4e ab [2] 4c aa [2] 57 ac [2] 4b ab [2] 57 84 }

  condition:
    any of them
}