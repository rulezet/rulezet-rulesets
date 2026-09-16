rule TTP_XOR_QUAD_CurrentVersionRun_08d5 {
  strings:
    $key_08d5 = { 5b ba [2] 7f b4 [2] 54 98 [2] 7a ba [2] 6e a1 [2] 61 bb [2] 7f a6 [2] 7d a7 [2] 66 a1 [2] 7a a6 [2] 66 89 }

  condition:
    any of them
}