rule TTP_XOR_QUAD_CurrentVersionRun_18d5 {
  strings:
    $key_18d5 = { 4b ba [2] 6f b4 [2] 44 98 [2] 6a ba [2] 7e a1 [2] 71 bb [2] 6f a6 [2] 6d a7 [2] 76 a1 [2] 6a a6 [2] 76 89 }

  condition:
    any of them
}