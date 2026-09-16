rule TTP_XOR_QUAD_CurrentVersionRun_45d4 {
  strings:
    $key_45d4 = { 16 bb [2] 32 b5 [2] 19 99 [2] 37 bb [2] 23 a0 [2] 2c ba [2] 32 a7 [2] 30 a6 [2] 2b a0 [2] 37 a7 [2] 2b 88 }

  condition:
    any of them
}