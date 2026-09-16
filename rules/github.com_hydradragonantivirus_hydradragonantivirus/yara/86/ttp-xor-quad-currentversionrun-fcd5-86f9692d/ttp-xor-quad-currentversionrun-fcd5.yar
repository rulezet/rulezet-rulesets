rule TTP_XOR_QUAD_CurrentVersionRun_fcd5 {
  strings:
    $key_fcd5 = { af ba [2] 8b b4 [2] a0 98 [2] 8e ba [2] 9a a1 [2] 95 bb [2] 8b a6 [2] 89 a7 [2] 92 a1 [2] 8e a6 [2] 92 89 }

  condition:
    any of them
}