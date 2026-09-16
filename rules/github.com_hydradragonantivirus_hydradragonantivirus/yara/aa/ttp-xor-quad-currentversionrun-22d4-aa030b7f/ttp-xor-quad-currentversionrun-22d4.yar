rule TTP_XOR_QUAD_CurrentVersionRun_22d4 {
  strings:
    $key_22d4 = { 71 bb [2] 55 b5 [2] 7e 99 [2] 50 bb [2] 44 a0 [2] 4b ba [2] 55 a7 [2] 57 a6 [2] 4c a0 [2] 50 a7 [2] 4c 88 }

  condition:
    any of them
}