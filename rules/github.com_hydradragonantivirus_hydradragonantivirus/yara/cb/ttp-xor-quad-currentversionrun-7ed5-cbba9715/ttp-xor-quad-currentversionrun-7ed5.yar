rule TTP_XOR_QUAD_CurrentVersionRun_7ed5 {
  strings:
    $key_7ed5 = { 2d ba [2] 09 b4 [2] 22 98 [2] 0c ba [2] 18 a1 [2] 17 bb [2] 09 a6 [2] 0b a7 [2] 10 a1 [2] 0c a6 [2] 10 89 }

  condition:
    any of them
}