rule TTP_XOR_QUAD_CurrentVersionRun_12d4 {
  strings:
    $key_12d4 = { 41 bb [2] 65 b5 [2] 4e 99 [2] 60 bb [2] 74 a0 [2] 7b ba [2] 65 a7 [2] 67 a6 [2] 7c a0 [2] 60 a7 [2] 7c 88 }

  condition:
    any of them
}