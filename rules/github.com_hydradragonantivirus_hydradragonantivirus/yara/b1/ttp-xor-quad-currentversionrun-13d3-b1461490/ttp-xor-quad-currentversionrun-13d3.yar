rule TTP_XOR_QUAD_CurrentVersionRun_13d3 {
  strings:
    $key_13d3 = { 40 bc [2] 64 b2 [2] 4f 9e [2] 61 bc [2] 75 a7 [2] 7a bd [2] 64 a0 [2] 66 a1 [2] 7d a7 [2] 61 a0 [2] 7d 8f }

  condition:
    any of them
}