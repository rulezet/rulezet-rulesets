rule TTP_XOR_QUAD_CurrentVersionRun_09d8 {
  strings:
    $key_09d8 = { 5a b7 [2] 7e b9 [2] 55 95 [2] 7b b7 [2] 6f ac [2] 60 b6 [2] 7e ab [2] 7c aa [2] 67 ac [2] 7b ab [2] 67 84 }

  condition:
    any of them
}