rule TTP_XOR_QUAD_CurrentVersionRun_c1d8 {
  strings:
    $key_c1d8 = { 92 b7 [2] b6 b9 [2] 9d 95 [2] b3 b7 [2] a7 ac [2] a8 b6 [2] b6 ab [2] b4 aa [2] af ac [2] b3 ab [2] af 84 }

  condition:
    any of them
}