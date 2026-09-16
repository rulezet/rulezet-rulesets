rule TTP_XOR_QUAD_CurrentVersionRun_46d4 {
  strings:
    $key_46d4 = { 15 bb [2] 31 b5 [2] 1a 99 [2] 34 bb [2] 20 a0 [2] 2f ba [2] 31 a7 [2] 33 a6 [2] 28 a0 [2] 34 a7 [2] 28 88 }

  condition:
    any of them
}