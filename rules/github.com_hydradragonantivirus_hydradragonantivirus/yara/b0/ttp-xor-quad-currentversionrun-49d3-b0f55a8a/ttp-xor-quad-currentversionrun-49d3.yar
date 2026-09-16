rule TTP_XOR_QUAD_CurrentVersionRun_49d3 {
  strings:
    $key_49d3 = { 1a bc [2] 3e b2 [2] 15 9e [2] 3b bc [2] 2f a7 [2] 20 bd [2] 3e a0 [2] 3c a1 [2] 27 a7 [2] 3b a0 [2] 27 8f }

  condition:
    any of them
}