rule TTP_XOR_QUAD_CurrentVersionRun_d4d8 {
  strings:
    $key_d4d8 = { 87 b7 [2] a3 b9 [2] 88 95 [2] a6 b7 [2] b2 ac [2] bd b6 [2] a3 ab [2] a1 aa [2] ba ac [2] a6 ab [2] ba 84 }

  condition:
    any of them
}