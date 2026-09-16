rule TTP_XOR_QUAD_CurrentVersionRun_50c9 {
  strings:
    $key_50c9 = { 03 a6 [2] 27 a8 [2] 0c 84 [2] 22 a6 [2] 36 bd [2] 39 a7 [2] 27 ba [2] 25 bb [2] 3e bd [2] 22 ba [2] 3e 95 }

  condition:
    any of them
}