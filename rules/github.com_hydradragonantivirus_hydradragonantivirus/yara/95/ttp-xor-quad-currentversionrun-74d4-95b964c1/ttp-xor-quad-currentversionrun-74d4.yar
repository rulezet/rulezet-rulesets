rule TTP_XOR_QUAD_CurrentVersionRun_74d4 {
  strings:
    $key_74d4 = { 27 bb [2] 03 b5 [2] 28 99 [2] 06 bb [2] 12 a0 [2] 1d ba [2] 03 a7 [2] 01 a6 [2] 1a a0 [2] 06 a7 [2] 1a 88 }

  condition:
    any of them
}