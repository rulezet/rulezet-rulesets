rule TTP_XOR_QUAD_CurrentVersionRun_d0d8 {
  strings:
    $key_d0d8 = { 83 b7 [2] a7 b9 [2] 8c 95 [2] a2 b7 [2] b6 ac [2] b9 b6 [2] a7 ab [2] a5 aa [2] be ac [2] a2 ab [2] be 84 }

  condition:
    any of them
}