rule TTP_XOR_QUAD_CurrentVersionRun_58d5 {
  strings:
    $key_58d5 = { 0b ba [2] 2f b4 [2] 04 98 [2] 2a ba [2] 3e a1 [2] 31 bb [2] 2f a6 [2] 2d a7 [2] 36 a1 [2] 2a a6 [2] 36 89 }

  condition:
    any of them
}