rule TTP_XOR_QUAD_CurrentVersionRun_6cd5 {
  strings:
    $key_6cd5 = { 3f ba [2] 1b b4 [2] 30 98 [2] 1e ba [2] 0a a1 [2] 05 bb [2] 1b a6 [2] 19 a7 [2] 02 a1 [2] 1e a6 [2] 02 89 }

  condition:
    any of them
}