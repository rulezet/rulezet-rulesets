rule TTP_XOR_QUAD_CurrentVersionRun_73d3 {
  strings:
    $key_73d3 = { 20 bc [2] 04 b2 [2] 2f 9e [2] 01 bc [2] 15 a7 [2] 1a bd [2] 04 a0 [2] 06 a1 [2] 1d a7 [2] 01 a0 [2] 1d 8f }

  condition:
    any of them
}