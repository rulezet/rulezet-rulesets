rule TTP_XOR_QUAD_CurrentVersionRun_10d3 {
  strings:
    $key_10d3 = { 43 bc [2] 67 b2 [2] 4c 9e [2] 62 bc [2] 76 a7 [2] 79 bd [2] 67 a0 [2] 65 a1 [2] 7e a7 [2] 62 a0 [2] 7e 8f }

  condition:
    any of them
}