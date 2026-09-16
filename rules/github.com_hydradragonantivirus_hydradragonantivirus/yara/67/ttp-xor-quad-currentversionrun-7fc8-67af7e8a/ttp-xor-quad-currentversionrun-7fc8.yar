rule TTP_XOR_QUAD_CurrentVersionRun_7fc8 {
  strings:
    $key_7fc8 = { 2c a7 [2] 08 a9 [2] 23 85 [2] 0d a7 [2] 19 bc [2] 16 a6 [2] 08 bb [2] 0a ba [2] 11 bc [2] 0d bb [2] 11 94 }

  condition:
    any of them
}