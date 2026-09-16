rule TTP_XOR_QUAD_CurrentVersionRun_fcd8 {
  strings:
    $key_fcd8 = { af b7 [2] 8b b9 [2] a0 95 [2] 8e b7 [2] 9a ac [2] 95 b6 [2] 8b ab [2] 89 aa [2] 92 ac [2] 8e ab [2] 92 84 }

  condition:
    any of them
}