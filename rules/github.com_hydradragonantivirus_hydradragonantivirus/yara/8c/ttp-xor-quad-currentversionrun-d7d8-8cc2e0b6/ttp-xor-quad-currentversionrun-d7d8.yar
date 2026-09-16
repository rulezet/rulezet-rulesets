rule TTP_XOR_QUAD_CurrentVersionRun_d7d8 {
  strings:
    $key_d7d8 = { 84 b7 [2] a0 b9 [2] 8b 95 [2] a5 b7 [2] b1 ac [2] be b6 [2] a0 ab [2] a2 aa [2] b9 ac [2] a5 ab [2] b9 84 }

  condition:
    any of them
}