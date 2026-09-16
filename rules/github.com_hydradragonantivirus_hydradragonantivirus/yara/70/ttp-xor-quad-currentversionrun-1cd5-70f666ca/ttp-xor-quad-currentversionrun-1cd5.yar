rule TTP_XOR_QUAD_CurrentVersionRun_1cd5 {
  strings:
    $key_1cd5 = { 4f ba [2] 6b b4 [2] 40 98 [2] 6e ba [2] 7a a1 [2] 75 bb [2] 6b a6 [2] 69 a7 [2] 72 a1 [2] 6e a6 [2] 72 89 }

  condition:
    any of them
}