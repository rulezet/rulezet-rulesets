rule TTP_XOR_QUAD_CurrentVersionRun_f9d8 {
  strings:
    $key_f9d8 = { aa b7 [2] 8e b9 [2] a5 95 [2] 8b b7 [2] 9f ac [2] 90 b6 [2] 8e ab [2] 8c aa [2] 97 ac [2] 8b ab [2] 97 84 }

  condition:
    any of them
}