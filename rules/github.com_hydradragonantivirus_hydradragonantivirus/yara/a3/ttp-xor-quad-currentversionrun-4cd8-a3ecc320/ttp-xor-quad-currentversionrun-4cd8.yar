rule TTP_XOR_QUAD_CurrentVersionRun_4cd8 {
  strings:
    $key_4cd8 = { 1f b7 [2] 3b b9 [2] 10 95 [2] 3e b7 [2] 2a ac [2] 25 b6 [2] 3b ab [2] 39 aa [2] 22 ac [2] 3e ab [2] 22 84 }

  condition:
    any of them
}