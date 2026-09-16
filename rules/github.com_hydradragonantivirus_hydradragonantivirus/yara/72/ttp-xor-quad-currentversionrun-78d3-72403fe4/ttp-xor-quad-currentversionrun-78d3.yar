rule TTP_XOR_QUAD_CurrentVersionRun_78d3 {
  strings:
    $key_78d3 = { 2b bc [2] 0f b2 [2] 24 9e [2] 0a bc [2] 1e a7 [2] 11 bd [2] 0f a0 [2] 0d a1 [2] 16 a7 [2] 0a a0 [2] 16 8f }

  condition:
    any of them
}