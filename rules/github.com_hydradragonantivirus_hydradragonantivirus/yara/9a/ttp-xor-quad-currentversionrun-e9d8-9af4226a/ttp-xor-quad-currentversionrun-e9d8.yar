rule TTP_XOR_QUAD_CurrentVersionRun_e9d8 {
  strings:
    $key_e9d8 = { ba b7 [2] 9e b9 [2] b5 95 [2] 9b b7 [2] 8f ac [2] 80 b6 [2] 9e ab [2] 9c aa [2] 87 ac [2] 9b ab [2] 87 84 }

  condition:
    any of them
}