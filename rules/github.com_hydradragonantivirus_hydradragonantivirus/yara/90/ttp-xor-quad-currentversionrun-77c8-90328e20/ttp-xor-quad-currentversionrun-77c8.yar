rule TTP_XOR_QUAD_CurrentVersionRun_77c8 {
  strings:
    $key_77c8 = { 24 a7 [2] 00 a9 [2] 2b 85 [2] 05 a7 [2] 11 bc [2] 1e a6 [2] 00 bb [2] 02 ba [2] 19 bc [2] 05 bb [2] 19 94 }

  condition:
    any of them
}