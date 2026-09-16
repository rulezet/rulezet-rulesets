rule TTP_XOR_QUAD_CurrentVersionRun_06d3 {
  strings:
    $key_06d3 = { 55 bc [2] 71 b2 [2] 5a 9e [2] 74 bc [2] 60 a7 [2] 6f bd [2] 71 a0 [2] 73 a1 [2] 68 a7 [2] 74 a0 [2] 68 8f }

  condition:
    any of them
}