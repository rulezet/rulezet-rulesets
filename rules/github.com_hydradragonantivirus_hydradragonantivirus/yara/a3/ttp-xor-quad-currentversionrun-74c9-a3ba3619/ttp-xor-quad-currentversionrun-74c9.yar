rule TTP_XOR_QUAD_CurrentVersionRun_74c9 {
  strings:
    $key_74c9 = { 27 a6 [2] 03 a8 [2] 28 84 [2] 06 a6 [2] 12 bd [2] 1d a7 [2] 03 ba [2] 01 bb [2] 1a bd [2] 06 ba [2] 1a 95 }

  condition:
    any of them
}