rule TTP_XOR_QUAD_CurrentVersionRun_60d5 {
  strings:
    $key_60d5 = { 33 ba [2] 17 b4 [2] 3c 98 [2] 12 ba [2] 06 a1 [2] 09 bb [2] 17 a6 [2] 15 a7 [2] 0e a1 [2] 12 a6 [2] 0e 89 }

  condition:
    any of them
}