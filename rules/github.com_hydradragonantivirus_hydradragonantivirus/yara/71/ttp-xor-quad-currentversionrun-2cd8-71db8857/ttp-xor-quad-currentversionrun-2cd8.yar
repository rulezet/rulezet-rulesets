rule TTP_XOR_QUAD_CurrentVersionRun_2cd8 {
  strings:
    $key_2cd8 = { 7f b7 [2] 5b b9 [2] 70 95 [2] 5e b7 [2] 4a ac [2] 45 b6 [2] 5b ab [2] 59 aa [2] 42 ac [2] 5e ab [2] 42 84 }

  condition:
    any of them
}