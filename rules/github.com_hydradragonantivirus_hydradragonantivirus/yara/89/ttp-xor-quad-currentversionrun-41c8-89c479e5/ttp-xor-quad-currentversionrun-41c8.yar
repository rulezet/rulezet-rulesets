rule TTP_XOR_QUAD_CurrentVersionRun_41c8 {
  strings:
    $key_41c8 = { 12 a7 [2] 36 a9 [2] 1d 85 [2] 33 a7 [2] 27 bc [2] 28 a6 [2] 36 bb [2] 34 ba [2] 2f bc [2] 33 bb [2] 2f 94 }

  condition:
    any of them
}