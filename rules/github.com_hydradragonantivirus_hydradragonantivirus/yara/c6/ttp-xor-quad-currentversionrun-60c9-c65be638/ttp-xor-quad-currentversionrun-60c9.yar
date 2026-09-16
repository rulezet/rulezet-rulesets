rule TTP_XOR_QUAD_CurrentVersionRun_60c9 {
  strings:
    $key_60c9 = { 33 a6 [2] 17 a8 [2] 3c 84 [2] 12 a6 [2] 06 bd [2] 09 a7 [2] 17 ba [2] 15 bb [2] 0e bd [2] 12 ba [2] 0e 95 }

  condition:
    any of them
}