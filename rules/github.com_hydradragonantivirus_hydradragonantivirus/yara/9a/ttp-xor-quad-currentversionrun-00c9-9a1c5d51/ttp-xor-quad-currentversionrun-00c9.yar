rule TTP_XOR_QUAD_CurrentVersionRun_00c9 {
  strings:
    $key_00c9 = { 53 a6 [2] 77 a8 [2] 5c 84 [2] 72 a6 [2] 66 bd [2] 69 a7 [2] 77 ba [2] 75 bb [2] 6e bd [2] 72 ba [2] 6e 95 }

  condition:
    any of them
}