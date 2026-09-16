rule TTP_XOR_QUAD_CurrentVersionRun_24c8 {
  strings:
    $key_24c8 = { 77 a7 [2] 53 a9 [2] 78 85 [2] 56 a7 [2] 42 bc [2] 4d a6 [2] 53 bb [2] 51 ba [2] 4a bc [2] 56 bb [2] 4a 94 }

  condition:
    any of them
}