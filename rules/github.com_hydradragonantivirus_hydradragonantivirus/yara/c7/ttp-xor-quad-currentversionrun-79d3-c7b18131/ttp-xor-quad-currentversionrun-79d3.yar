rule TTP_XOR_QUAD_CurrentVersionRun_79d3 {
  strings:
    $key_79d3 = { 2a bc [2] 0e b2 [2] 25 9e [2] 0b bc [2] 1f a7 [2] 10 bd [2] 0e a0 [2] 0c a1 [2] 17 a7 [2] 0b a0 [2] 17 8f }

  condition:
    any of them
}