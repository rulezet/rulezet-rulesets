rule TTP_XOR_QUAD_CurrentVersionRun_41c9 {
  strings:
    $key_41c9 = { 12 a6 [2] 36 a8 [2] 1d 84 [2] 33 a6 [2] 27 bd [2] 28 a7 [2] 36 ba [2] 34 bb [2] 2f bd [2] 33 ba [2] 2f 95 }

  condition:
    any of them
}