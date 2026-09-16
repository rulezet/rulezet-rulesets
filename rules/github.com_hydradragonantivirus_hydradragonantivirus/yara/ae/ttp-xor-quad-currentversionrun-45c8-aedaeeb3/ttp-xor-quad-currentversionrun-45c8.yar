rule TTP_XOR_QUAD_CurrentVersionRun_45c8 {
  strings:
    $key_45c8 = { 16 a7 [2] 32 a9 [2] 19 85 [2] 37 a7 [2] 23 bc [2] 2c a6 [2] 32 bb [2] 30 ba [2] 2b bc [2] 37 bb [2] 2b 94 }

  condition:
    any of them
}