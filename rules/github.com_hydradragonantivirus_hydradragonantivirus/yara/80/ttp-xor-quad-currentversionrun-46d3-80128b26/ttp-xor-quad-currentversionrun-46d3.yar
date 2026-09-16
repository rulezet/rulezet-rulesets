rule TTP_XOR_QUAD_CurrentVersionRun_46d3 {
  strings:
    $key_46d3 = { 15 bc [2] 31 b2 [2] 1a 9e [2] 34 bc [2] 20 a7 [2] 2f bd [2] 31 a0 [2] 33 a1 [2] 28 a7 [2] 34 a0 [2] 28 8f }

  condition:
    any of them
}