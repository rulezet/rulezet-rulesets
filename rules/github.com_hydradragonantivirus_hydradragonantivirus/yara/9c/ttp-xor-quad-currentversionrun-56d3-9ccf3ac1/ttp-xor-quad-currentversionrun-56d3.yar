rule TTP_XOR_QUAD_CurrentVersionRun_56d3 {
  strings:
    $key_56d3 = { 05 bc [2] 21 b2 [2] 0a 9e [2] 24 bc [2] 30 a7 [2] 3f bd [2] 21 a0 [2] 23 a1 [2] 38 a7 [2] 24 a0 [2] 38 8f }

  condition:
    any of them
}