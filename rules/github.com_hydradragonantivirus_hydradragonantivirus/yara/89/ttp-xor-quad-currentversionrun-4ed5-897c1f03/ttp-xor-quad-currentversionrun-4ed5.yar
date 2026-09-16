rule TTP_XOR_QUAD_CurrentVersionRun_4ed5 {
  strings:
    $key_4ed5 = { 1d ba [2] 39 b4 [2] 12 98 [2] 3c ba [2] 28 a1 [2] 27 bb [2] 39 a6 [2] 3b a7 [2] 20 a1 [2] 3c a6 [2] 20 89 }

  condition:
    any of them
}