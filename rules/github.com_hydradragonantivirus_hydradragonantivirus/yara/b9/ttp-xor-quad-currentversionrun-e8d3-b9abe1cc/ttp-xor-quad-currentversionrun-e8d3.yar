rule TTP_XOR_QUAD_CurrentVersionRun_e8d3 {
  strings:
    $key_e8d3 = { bb bc [2] 9f b2 [2] b4 9e [2] 9a bc [2] 8e a7 [2] 81 bd [2] 9f a0 [2] 9d a1 [2] 86 a7 [2] 9a a0 [2] 86 8f }

  condition:
    any of them
}