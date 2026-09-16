rule TTP_XOR_QUAD_CurrentVersionRun_f5d4 {
  strings:
    $key_f5d4 = { a6 bb [2] 82 b5 [2] a9 99 [2] 87 bb [2] 93 a0 [2] 9c ba [2] 82 a7 [2] 80 a6 [2] 9b a0 [2] 87 a7 [2] 9b 88 }

  condition:
    any of them
}