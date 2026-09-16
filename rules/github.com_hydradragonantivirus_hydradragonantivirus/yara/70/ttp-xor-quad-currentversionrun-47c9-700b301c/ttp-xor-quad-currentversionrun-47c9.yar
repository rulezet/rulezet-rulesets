rule TTP_XOR_QUAD_CurrentVersionRun_47c9 {
  strings:
    $key_47c9 = { 14 a6 [2] 30 a8 [2] 1b 84 [2] 35 a6 [2] 21 bd [2] 2e a7 [2] 30 ba [2] 32 bb [2] 29 bd [2] 35 ba [2] 29 95 }

  condition:
    any of them
}