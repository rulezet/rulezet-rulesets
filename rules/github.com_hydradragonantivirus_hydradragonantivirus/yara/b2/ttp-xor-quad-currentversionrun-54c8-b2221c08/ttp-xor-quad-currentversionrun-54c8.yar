rule TTP_XOR_QUAD_CurrentVersionRun_54c8 {
  strings:
    $key_54c8 = { 07 a7 [2] 23 a9 [2] 08 85 [2] 26 a7 [2] 32 bc [2] 3d a6 [2] 23 bb [2] 21 ba [2] 3a bc [2] 26 bb [2] 3a 94 }

  condition:
    any of them
}