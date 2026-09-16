rule TTP_XOR_QUAD_CurrentVersionRun_f4d3 {
  strings:
    $key_f4d3 = { a7 bc [2] 83 b2 [2] a8 9e [2] 86 bc [2] 92 a7 [2] 9d bd [2] 83 a0 [2] 81 a1 [2] 9a a7 [2] 86 a0 [2] 9a 8f }

  condition:
    any of them
}