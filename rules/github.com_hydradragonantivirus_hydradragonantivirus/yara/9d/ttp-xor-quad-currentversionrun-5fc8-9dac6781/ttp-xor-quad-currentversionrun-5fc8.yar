rule TTP_XOR_QUAD_CurrentVersionRun_5fc8 {
  strings:
    $key_5fc8 = { 0c a7 [2] 28 a9 [2] 03 85 [2] 2d a7 [2] 39 bc [2] 36 a6 [2] 28 bb [2] 2a ba [2] 31 bc [2] 2d bb [2] 31 94 }

  condition:
    any of them
}