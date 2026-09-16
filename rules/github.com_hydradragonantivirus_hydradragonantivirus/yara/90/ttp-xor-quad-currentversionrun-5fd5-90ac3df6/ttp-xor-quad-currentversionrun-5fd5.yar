rule TTP_XOR_QUAD_CurrentVersionRun_5fd5 {
  strings:
    $key_5fd5 = { 0c ba [2] 28 b4 [2] 03 98 [2] 2d ba [2] 39 a1 [2] 36 bb [2] 28 a6 [2] 2a a7 [2] 31 a1 [2] 2d a6 [2] 31 89 }

  condition:
    any of them
}