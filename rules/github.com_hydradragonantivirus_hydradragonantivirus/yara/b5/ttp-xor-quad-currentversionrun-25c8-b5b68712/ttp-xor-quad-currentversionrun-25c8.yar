rule TTP_XOR_QUAD_CurrentVersionRun_25c8 {
  strings:
    $key_25c8 = { 76 a7 [2] 52 a9 [2] 79 85 [2] 57 a7 [2] 43 bc [2] 4c a6 [2] 52 bb [2] 50 ba [2] 4b bc [2] 57 bb [2] 4b 94 }

  condition:
    any of them
}