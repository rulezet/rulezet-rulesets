rule TTP_XOR_QUAD_CurrentVersionRun_26d3 {
  strings:
    $key_26d3 = { 75 bc [2] 51 b2 [2] 7a 9e [2] 54 bc [2] 40 a7 [2] 4f bd [2] 51 a0 [2] 53 a1 [2] 48 a7 [2] 54 a0 [2] 48 8f }

  condition:
    any of them
}