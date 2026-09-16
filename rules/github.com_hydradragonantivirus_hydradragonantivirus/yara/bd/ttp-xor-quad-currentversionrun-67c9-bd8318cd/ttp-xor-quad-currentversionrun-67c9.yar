rule TTP_XOR_QUAD_CurrentVersionRun_67c9 {
  strings:
    $key_67c9 = { 34 a6 [2] 10 a8 [2] 3b 84 [2] 15 a6 [2] 01 bd [2] 0e a7 [2] 10 ba [2] 12 bb [2] 09 bd [2] 15 ba [2] 09 95 }

  condition:
    any of them
}