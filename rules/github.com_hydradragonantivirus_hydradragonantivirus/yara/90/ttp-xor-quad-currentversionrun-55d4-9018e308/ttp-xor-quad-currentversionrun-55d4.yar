rule TTP_XOR_QUAD_CurrentVersionRun_55d4 {
  strings:
    $key_55d4 = { 06 bb [2] 22 b5 [2] 09 99 [2] 27 bb [2] 33 a0 [2] 3c ba [2] 22 a7 [2] 20 a6 [2] 3b a0 [2] 27 a7 [2] 3b 88 }

  condition:
    any of them
}