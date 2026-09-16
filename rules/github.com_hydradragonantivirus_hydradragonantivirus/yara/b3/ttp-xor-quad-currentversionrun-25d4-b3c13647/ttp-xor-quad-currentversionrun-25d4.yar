rule TTP_XOR_QUAD_CurrentVersionRun_25d4 {
  strings:
    $key_25d4 = { 76 bb [2] 52 b5 [2] 79 99 [2] 57 bb [2] 43 a0 [2] 4c ba [2] 52 a7 [2] 50 a6 [2] 4b a0 [2] 57 a7 [2] 4b 88 }

  condition:
    any of them
}