rule TTP_XOR_QUAD_CurrentVersionRun_5cd5 {
  strings:
    $key_5cd5 = { 0f ba [2] 2b b4 [2] 00 98 [2] 2e ba [2] 3a a1 [2] 35 bb [2] 2b a6 [2] 29 a7 [2] 32 a1 [2] 2e a6 [2] 32 89 }

  condition:
    any of them
}