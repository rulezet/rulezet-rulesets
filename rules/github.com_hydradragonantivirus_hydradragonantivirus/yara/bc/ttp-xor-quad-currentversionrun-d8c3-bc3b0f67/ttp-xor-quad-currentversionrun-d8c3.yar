rule TTP_XOR_QUAD_CurrentVersionRun_d8c3 {
  strings:
    $key_d8c3 = { 8b ac [2] af a2 [2] 84 8e [2] aa ac [2] be b7 [2] b1 ad [2] af b0 [2] ad b1 [2] b6 b7 [2] aa b0 [2] b6 9f }

  condition:
    any of them
}