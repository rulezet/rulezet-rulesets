rule TTP_XOR_QUAD_CurrentVersionRun_10d4 {
  strings:
    $key_10d4 = { 43 bb [2] 67 b5 [2] 4c 99 [2] 62 bb [2] 76 a0 [2] 79 ba [2] 67 a7 [2] 65 a6 [2] 7e a0 [2] 62 a7 [2] 7e 88 }

  condition:
    any of them
}