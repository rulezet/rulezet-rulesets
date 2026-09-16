rule TTP_XOR_QUAD_CurrentVersionRun_64d3 {
  strings:
    $key_64d3 = { 37 bc [2] 13 b2 [2] 38 9e [2] 16 bc [2] 02 a7 [2] 0d bd [2] 13 a0 [2] 11 a1 [2] 0a a7 [2] 16 a0 [2] 0a 8f }

  condition:
    any of them
}