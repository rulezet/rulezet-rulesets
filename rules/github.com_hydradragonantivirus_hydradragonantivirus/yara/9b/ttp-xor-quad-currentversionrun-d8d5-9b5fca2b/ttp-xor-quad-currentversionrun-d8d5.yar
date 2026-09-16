rule TTP_XOR_QUAD_CurrentVersionRun_d8d5 {
  strings:
    $key_d8d5 = { 8b ba [2] af b4 [2] 84 98 [2] aa ba [2] be a1 [2] b1 bb [2] af a6 [2] ad a7 [2] b6 a1 [2] aa a6 [2] b6 89 }

  condition:
    any of them
}