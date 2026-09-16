rule TTP_XOR_QUAD_CurrentVersionRun_43d4 {
  strings:
    $key_43d4 = { 10 bb [2] 34 b5 [2] 1f 99 [2] 31 bb [2] 25 a0 [2] 2a ba [2] 34 a7 [2] 36 a6 [2] 2d a0 [2] 31 a7 [2] 2d 88 }

  condition:
    any of them
}