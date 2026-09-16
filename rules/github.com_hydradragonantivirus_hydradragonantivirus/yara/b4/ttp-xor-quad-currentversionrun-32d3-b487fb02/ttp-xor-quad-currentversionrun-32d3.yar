rule TTP_XOR_QUAD_CurrentVersionRun_32d3 {
  strings:
    $key_32d3 = { 61 bc [2] 45 b2 [2] 6e 9e [2] 40 bc [2] 54 a7 [2] 5b bd [2] 45 a0 [2] 47 a1 [2] 5c a7 [2] 40 a0 [2] 5c 8f }

  condition:
    any of them
}