rule TTP_XOR_QUAD_CurrentVersionRun_71c8 {
  strings:
    $key_71c8 = { 22 a7 [2] 06 a9 [2] 2d 85 [2] 03 a7 [2] 17 bc [2] 18 a6 [2] 06 bb [2] 04 ba [2] 1f bc [2] 03 bb [2] 1f 94 }

  condition:
    any of them
}