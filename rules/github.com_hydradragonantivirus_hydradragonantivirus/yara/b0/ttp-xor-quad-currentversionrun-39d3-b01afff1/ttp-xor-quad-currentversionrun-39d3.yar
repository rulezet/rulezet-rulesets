rule TTP_XOR_QUAD_CurrentVersionRun_39d3 {
  strings:
    $key_39d3 = { 6a bc [2] 4e b2 [2] 65 9e [2] 4b bc [2] 5f a7 [2] 50 bd [2] 4e a0 [2] 4c a1 [2] 57 a7 [2] 4b a0 [2] 57 8f }

  condition:
    any of them
}