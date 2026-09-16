rule TTP_XOR_QUAD_CurrentVersionRun_4ec8 {
  strings:
    $key_4ec8 = { 1d a7 [2] 39 a9 [2] 12 85 [2] 3c a7 [2] 28 bc [2] 27 a6 [2] 39 bb [2] 3b ba [2] 20 bc [2] 3c bb [2] 20 94 }

  condition:
    any of them
}