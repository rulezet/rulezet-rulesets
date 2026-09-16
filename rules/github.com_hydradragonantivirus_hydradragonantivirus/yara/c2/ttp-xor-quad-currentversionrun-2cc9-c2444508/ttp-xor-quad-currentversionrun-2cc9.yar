rule TTP_XOR_QUAD_CurrentVersionRun_2cc9 {
  strings:
    $key_2cc9 = { 7f a6 [2] 5b a8 [2] 70 84 [2] 5e a6 [2] 4a bd [2] 45 a7 [2] 5b ba [2] 59 bb [2] 42 bd [2] 5e ba [2] 42 95 }

  condition:
    any of them
}