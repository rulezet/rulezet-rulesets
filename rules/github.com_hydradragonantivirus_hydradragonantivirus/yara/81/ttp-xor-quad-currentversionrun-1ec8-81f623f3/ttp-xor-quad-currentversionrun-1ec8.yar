rule TTP_XOR_QUAD_CurrentVersionRun_1ec8 {
  strings:
    $key_1ec8 = { 4d a7 [2] 69 a9 [2] 42 85 [2] 6c a7 [2] 78 bc [2] 77 a6 [2] 69 bb [2] 6b ba [2] 70 bc [2] 6c bb [2] 70 94 }

  condition:
    any of them
}