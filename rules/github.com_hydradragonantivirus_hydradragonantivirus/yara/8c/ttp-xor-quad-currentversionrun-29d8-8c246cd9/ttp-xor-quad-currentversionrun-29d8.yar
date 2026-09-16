rule TTP_XOR_QUAD_CurrentVersionRun_29d8 {
  strings:
    $key_29d8 = { 7a b7 [2] 5e b9 [2] 75 95 [2] 5b b7 [2] 4f ac [2] 40 b6 [2] 5e ab [2] 5c aa [2] 47 ac [2] 5b ab [2] 47 84 }

  condition:
    any of them
}