rule TTP_XOR_QUAD_CurrentVersionRun_2cd5 {
  strings:
    $key_2cd5 = { 7f ba [2] 5b b4 [2] 70 98 [2] 5e ba [2] 4a a1 [2] 45 bb [2] 5b a6 [2] 59 a7 [2] 42 a1 [2] 5e a6 [2] 42 89 }

  condition:
    any of them
}