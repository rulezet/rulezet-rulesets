rule TTP_XOR_QUAD_CurrentVersionRun_f6d3 {
  strings:
    $key_f6d3 = { a5 bc [2] 81 b2 [2] aa 9e [2] 84 bc [2] 90 a7 [2] 9f bd [2] 81 a0 [2] 83 a1 [2] 98 a7 [2] 84 a0 [2] 98 8f }

  condition:
    any of them
}