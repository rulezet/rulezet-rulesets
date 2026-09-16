rule TTP_XOR_QUAD_CurrentVersionRun_dfd8 {
  strings:
    $key_dfd8 = { 8c b7 [2] a8 b9 [2] 83 95 [2] ad b7 [2] b9 ac [2] b6 b6 [2] a8 ab [2] aa aa [2] b1 ac [2] ad ab [2] b1 84 }

  condition:
    any of them
}