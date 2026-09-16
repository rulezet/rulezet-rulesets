rule TTP_XOR_QUAD_CurrentVersionRun_6fd5 {
  strings:
    $key_6fd5 = { 3c ba [2] 18 b4 [2] 33 98 [2] 1d ba [2] 09 a1 [2] 06 bb [2] 18 a6 [2] 1a a7 [2] 01 a1 [2] 1d a6 [2] 01 89 }

  condition:
    any of them
}