rule TTP_XOR_QUAD_CurrentVersionRun_c6d8 {
  strings:
    $key_c6d8 = { 95 b7 [2] b1 b9 [2] 9a 95 [2] b4 b7 [2] a0 ac [2] af b6 [2] b1 ab [2] b3 aa [2] a8 ac [2] b4 ab [2] a8 84 }

  condition:
    any of them
}