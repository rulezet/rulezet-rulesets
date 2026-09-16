rule TTP_XOR_QUAD_CurrentVersionRun_e4d3 {
  strings:
    $key_e4d3 = { b7 bc [2] 93 b2 [2] b8 9e [2] 96 bc [2] 82 a7 [2] 8d bd [2] 93 a0 [2] 91 a1 [2] 8a a7 [2] 96 a0 [2] 8a 8f }

  condition:
    any of them
}