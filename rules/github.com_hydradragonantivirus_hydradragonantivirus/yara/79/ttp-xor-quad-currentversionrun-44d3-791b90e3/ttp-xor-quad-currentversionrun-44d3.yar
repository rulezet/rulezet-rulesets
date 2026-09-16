rule TTP_XOR_QUAD_CurrentVersionRun_44d3 {
  strings:
    $key_44d3 = { 17 bc [2] 33 b2 [2] 18 9e [2] 36 bc [2] 22 a7 [2] 2d bd [2] 33 a0 [2] 31 a1 [2] 2a a7 [2] 36 a0 [2] 2a 8f }

  condition:
    any of them
}