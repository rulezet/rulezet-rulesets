rule TTP_XOR_QUAD_CurrentVersionRun_d8d3 {
  strings:
    $key_d8d3 = { 8b bc [2] af b2 [2] 84 9e [2] aa bc [2] be a7 [2] b1 bd [2] af a0 [2] ad a1 [2] b6 a7 [2] aa a0 [2] b6 8f }

  condition:
    any of them
}