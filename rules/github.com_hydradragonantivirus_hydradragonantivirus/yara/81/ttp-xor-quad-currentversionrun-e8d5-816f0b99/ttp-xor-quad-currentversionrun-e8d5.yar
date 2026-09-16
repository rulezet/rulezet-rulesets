rule TTP_XOR_QUAD_CurrentVersionRun_e8d5 {
  strings:
    $key_e8d5 = { bb ba [2] 9f b4 [2] b4 98 [2] 9a ba [2] 8e a1 [2] 81 bb [2] 9f a6 [2] 9d a7 [2] 86 a1 [2] 9a a6 [2] 86 89 }

  condition:
    any of them
}