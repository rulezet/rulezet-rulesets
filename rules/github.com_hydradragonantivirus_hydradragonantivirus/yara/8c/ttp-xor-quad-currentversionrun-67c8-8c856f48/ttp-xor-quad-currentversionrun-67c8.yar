rule TTP_XOR_QUAD_CurrentVersionRun_67c8 {
  strings:
    $key_67c8 = { 34 a7 [2] 10 a9 [2] 3b 85 [2] 15 a7 [2] 01 bc [2] 0e a6 [2] 10 bb [2] 12 ba [2] 09 bc [2] 15 bb [2] 09 94 }

  condition:
    any of them
}