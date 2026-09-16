rule TTP_XOR_QUAD_CurrentVersionRun_08d3 {
  strings:
    $key_08d3 = { 5b bc [2] 7f b2 [2] 54 9e [2] 7a bc [2] 6e a7 [2] 61 bd [2] 7f a0 [2] 7d a1 [2] 66 a7 [2] 7a a0 [2] 66 8f }

  condition:
    any of them
}