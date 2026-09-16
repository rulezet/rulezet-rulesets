rule TTP_XOR_QUAD_CurrentVersionRun_29d5 {
  strings:
    $key_29d5 = { 7a ba [2] 5e b4 [2] 75 98 [2] 5b ba [2] 4f a1 [2] 40 bb [2] 5e a6 [2] 5c a7 [2] 47 a1 [2] 5b a6 [2] 47 89 }

  condition:
    any of them
}