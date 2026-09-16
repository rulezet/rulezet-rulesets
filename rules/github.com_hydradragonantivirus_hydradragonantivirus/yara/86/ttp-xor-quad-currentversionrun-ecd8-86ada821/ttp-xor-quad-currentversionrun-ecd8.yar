rule TTP_XOR_QUAD_CurrentVersionRun_ecd8 {
  strings:
    $key_ecd8 = { bf b7 [2] 9b b9 [2] b0 95 [2] 9e b7 [2] 8a ac [2] 85 b6 [2] 9b ab [2] 99 aa [2] 82 ac [2] 9e ab [2] 82 84 }

  condition:
    any of them
}