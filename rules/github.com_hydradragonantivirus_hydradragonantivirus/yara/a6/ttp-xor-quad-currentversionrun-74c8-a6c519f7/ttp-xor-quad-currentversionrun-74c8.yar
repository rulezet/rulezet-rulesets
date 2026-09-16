rule TTP_XOR_QUAD_CurrentVersionRun_74c8 {
  strings:
    $key_74c8 = { 27 a7 [2] 03 a9 [2] 28 85 [2] 06 a7 [2] 12 bc [2] 1d a6 [2] 03 bb [2] 01 ba [2] 1a bc [2] 06 bb [2] 1a 94 }

  condition:
    any of them
}