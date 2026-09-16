rule TTP_XOR_QUAD_CurrentVersionRun_64c8 {
  strings:
    $key_64c8 = { 37 a7 [2] 13 a9 [2] 38 85 [2] 16 a7 [2] 02 bc [2] 0d a6 [2] 13 bb [2] 11 ba [2] 0a bc [2] 16 bb [2] 0a 94 }

  condition:
    any of them
}