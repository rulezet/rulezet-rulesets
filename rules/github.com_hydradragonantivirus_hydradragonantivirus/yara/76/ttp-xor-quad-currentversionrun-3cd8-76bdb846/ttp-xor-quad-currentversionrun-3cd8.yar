rule TTP_XOR_QUAD_CurrentVersionRun_3cd8 {
  strings:
    $key_3cd8 = { 6f b7 [2] 4b b9 [2] 60 95 [2] 4e b7 [2] 5a ac [2] 55 b6 [2] 4b ab [2] 49 aa [2] 52 ac [2] 4e ab [2] 52 84 }

  condition:
    any of them
}