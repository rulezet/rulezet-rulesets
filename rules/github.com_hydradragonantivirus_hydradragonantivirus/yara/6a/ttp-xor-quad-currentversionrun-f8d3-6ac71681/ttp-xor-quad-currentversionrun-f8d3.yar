rule TTP_XOR_QUAD_CurrentVersionRun_f8d3 {
  strings:
    $key_f8d3 = { ab bc [2] 8f b2 [2] a4 9e [2] 8a bc [2] 9e a7 [2] 91 bd [2] 8f a0 [2] 8d a1 [2] 96 a7 [2] 8a a0 [2] 96 8f }

  condition:
    any of them
}