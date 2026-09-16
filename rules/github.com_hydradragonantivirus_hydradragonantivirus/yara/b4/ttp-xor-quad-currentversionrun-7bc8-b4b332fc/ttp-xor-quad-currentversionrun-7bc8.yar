rule TTP_XOR_QUAD_CurrentVersionRun_7bc8 {
  strings:
    $key_7bc8 = { 28 a7 [2] 0c a9 [2] 27 85 [2] 09 a7 [2] 1d bc [2] 12 a6 [2] 0c bb [2] 0e ba [2] 15 bc [2] 09 bb [2] 15 94 }

  condition:
    any of them
}