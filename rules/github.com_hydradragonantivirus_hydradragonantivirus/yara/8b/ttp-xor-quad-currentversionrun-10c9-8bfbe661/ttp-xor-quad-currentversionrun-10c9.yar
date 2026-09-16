rule TTP_XOR_QUAD_CurrentVersionRun_10c9 {
  strings:
    $key_10c9 = { 43 a6 [2] 67 a8 [2] 4c 84 [2] 62 a6 [2] 76 bd [2] 79 a7 [2] 67 ba [2] 65 bb [2] 7e bd [2] 62 ba [2] 7e 95 }

  condition:
    any of them
}