rule TTP_XOR_QUAD_CurrentVersionRun_09d3 {
  strings:
    $key_09d3 = { 5a bc [2] 7e b2 [2] 55 9e [2] 7b bc [2] 6f a7 [2] 60 bd [2] 7e a0 [2] 7c a1 [2] 67 a7 [2] 7b a0 [2] 67 8f }

  condition:
    any of them
}