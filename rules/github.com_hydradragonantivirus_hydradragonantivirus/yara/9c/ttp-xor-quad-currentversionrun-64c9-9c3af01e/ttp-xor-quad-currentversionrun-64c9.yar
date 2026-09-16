rule TTP_XOR_QUAD_CurrentVersionRun_64c9 {
  strings:
    $key_64c9 = { 37 a6 [2] 13 a8 [2] 38 84 [2] 16 a6 [2] 02 bd [2] 0d a7 [2] 13 ba [2] 11 bb [2] 0a bd [2] 16 ba [2] 0a 95 }

  condition:
    any of them
}