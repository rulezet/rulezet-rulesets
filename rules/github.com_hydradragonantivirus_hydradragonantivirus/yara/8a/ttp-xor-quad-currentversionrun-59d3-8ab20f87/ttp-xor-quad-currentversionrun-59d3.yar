rule TTP_XOR_QUAD_CurrentVersionRun_59d3 {
  strings:
    $key_59d3 = { 0a bc [2] 2e b2 [2] 05 9e [2] 2b bc [2] 3f a7 [2] 30 bd [2] 2e a0 [2] 2c a1 [2] 37 a7 [2] 2b a0 [2] 37 8f }

  condition:
    any of them
}