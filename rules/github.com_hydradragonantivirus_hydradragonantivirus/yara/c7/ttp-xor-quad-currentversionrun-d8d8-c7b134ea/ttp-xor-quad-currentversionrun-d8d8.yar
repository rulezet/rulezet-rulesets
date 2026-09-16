rule TTP_XOR_QUAD_CurrentVersionRun_d8d8 {
  strings:
    $key_d8d8 = { 8b b7 [2] af b9 [2] 84 95 [2] aa b7 [2] be ac [2] b1 b6 [2] af ab [2] ad aa [2] b6 ac [2] aa ab [2] b6 84 }

  condition:
    any of them
}