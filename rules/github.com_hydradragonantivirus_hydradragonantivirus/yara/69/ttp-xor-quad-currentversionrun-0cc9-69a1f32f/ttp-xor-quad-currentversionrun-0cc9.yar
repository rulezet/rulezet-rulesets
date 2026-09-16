rule TTP_XOR_QUAD_CurrentVersionRun_0cc9 {
  strings:
    $key_0cc9 = { 5f a6 [2] 7b a8 [2] 50 84 [2] 7e a6 [2] 6a bd [2] 65 a7 [2] 7b ba [2] 79 bb [2] 62 bd [2] 7e ba [2] 62 95 }

  condition:
    any of them
}