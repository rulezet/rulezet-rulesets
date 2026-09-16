rule TTP_XOR_QUAD_CurrentVersionRun_54c9 {
  strings:
    $key_54c9 = { 07 a6 [2] 23 a8 [2] 08 84 [2] 26 a6 [2] 32 bd [2] 3d a7 [2] 23 ba [2] 21 bb [2] 3a bd [2] 26 ba [2] 3a 95 }

  condition:
    any of them
}