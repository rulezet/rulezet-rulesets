rule TTP_XOR_QUAD_CurrentVersionRun_95d4 {
  strings:
    $key_95d4 = { c6 bb [2] e2 b5 [2] c9 99 [2] e7 bb [2] f3 a0 [2] fc ba [2] e2 a7 [2] e0 a6 [2] fb a0 [2] e7 a7 [2] fb 88 }

  condition:
    any of them
}