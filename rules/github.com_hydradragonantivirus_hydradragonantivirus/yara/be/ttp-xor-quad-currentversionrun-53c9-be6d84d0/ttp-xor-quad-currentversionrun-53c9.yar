rule TTP_XOR_QUAD_CurrentVersionRun_53c9 {
  strings:
    $key_53c9 = { 00 a6 [2] 24 a8 [2] 0f 84 [2] 21 a6 [2] 35 bd [2] 3a a7 [2] 24 ba [2] 26 bb [2] 3d bd [2] 21 ba [2] 3d 95 }

  condition:
    any of them
}