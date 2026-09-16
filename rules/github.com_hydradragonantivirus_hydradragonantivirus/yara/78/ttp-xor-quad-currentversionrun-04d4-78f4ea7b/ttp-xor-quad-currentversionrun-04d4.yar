rule TTP_XOR_QUAD_CurrentVersionRun_04d4 {
  strings:
    $key_04d4 = { 57 bb [2] 73 b5 [2] 58 99 [2] 76 bb [2] 62 a0 [2] 6d ba [2] 73 a7 [2] 71 a6 [2] 6a a0 [2] 76 a7 [2] 6a 88 }

  condition:
    any of them
}