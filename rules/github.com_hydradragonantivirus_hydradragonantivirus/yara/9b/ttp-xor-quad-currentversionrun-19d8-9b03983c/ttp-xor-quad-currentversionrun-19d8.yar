rule TTP_XOR_QUAD_CurrentVersionRun_19d8 {
  strings:
    $key_19d8 = { 4a b7 [2] 6e b9 [2] 45 95 [2] 6b b7 [2] 7f ac [2] 70 b6 [2] 6e ab [2] 6c aa [2] 77 ac [2] 6b ab [2] 77 84 }

  condition:
    any of them
}