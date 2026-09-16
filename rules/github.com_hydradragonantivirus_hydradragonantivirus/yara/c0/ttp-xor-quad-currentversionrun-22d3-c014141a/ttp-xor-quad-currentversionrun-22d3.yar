rule TTP_XOR_QUAD_CurrentVersionRun_22d3 {
  strings:
    $key_22d3 = { 71 bc [2] 55 b2 [2] 7e 9e [2] 50 bc [2] 44 a7 [2] 4b bd [2] 55 a0 [2] 57 a1 [2] 4c a7 [2] 50 a0 [2] 4c 8f }

  condition:
    any of them
}