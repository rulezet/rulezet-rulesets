rule TTP_XOR_QUAD_CurrentVersionRun_5dd5 {
  strings:
    $key_5dd5 = { 0e ba [2] 2a b4 [2] 01 98 [2] 2f ba [2] 3b a1 [2] 34 bb [2] 2a a6 [2] 28 a7 [2] 33 a1 [2] 2f a6 [2] 33 89 }

  condition:
    any of them
}