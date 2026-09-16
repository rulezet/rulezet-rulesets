rule TTP_XOR_QUAD_CurrentVersionRun_48d3 {
  strings:
    $key_48d3 = { 1b bc [2] 3f b2 [2] 14 9e [2] 3a bc [2] 2e a7 [2] 21 bd [2] 3f a0 [2] 3d a1 [2] 26 a7 [2] 3a a0 [2] 26 8f }

  condition:
    any of them
}