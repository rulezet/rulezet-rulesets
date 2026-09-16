rule TTP_XOR_QUAD_CurrentVersionRun_38d5 {
  strings:
    $key_38d5 = { 6b ba [2] 4f b4 [2] 64 98 [2] 4a ba [2] 5e a1 [2] 51 bb [2] 4f a6 [2] 4d a7 [2] 56 a1 [2] 4a a6 [2] 56 89 }

  condition:
    any of them
}