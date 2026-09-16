rule TTP_XOR_QUAD_CurrentVersionRun_67d4 {
  strings:
    $key_67d4 = { 34 bb [2] 10 b5 [2] 3b 99 [2] 15 bb [2] 01 a0 [2] 0e ba [2] 10 a7 [2] 12 a6 [2] 09 a0 [2] 15 a7 [2] 09 88 }

  condition:
    any of them
}