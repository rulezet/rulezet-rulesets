rule TTP_XOR_QUAD_CurrentVersionRun_50d3 {
  strings:
    $key_50d3 = { 03 bc [2] 27 b2 [2] 0c 9e [2] 22 bc [2] 36 a7 [2] 39 bd [2] 27 a0 [2] 25 a1 [2] 3e a7 [2] 22 a0 [2] 3e 8f }

  condition:
    any of them
}