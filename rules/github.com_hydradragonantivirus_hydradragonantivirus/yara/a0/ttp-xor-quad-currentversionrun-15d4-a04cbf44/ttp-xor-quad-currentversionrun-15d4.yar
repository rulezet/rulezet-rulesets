rule TTP_XOR_QUAD_CurrentVersionRun_15d4 {
  strings:
    $key_15d4 = { 46 bb [2] 62 b5 [2] 49 99 [2] 67 bb [2] 73 a0 [2] 7c ba [2] 62 a7 [2] 60 a6 [2] 7b a0 [2] 67 a7 [2] 7b 88 }

  condition:
    any of them
}