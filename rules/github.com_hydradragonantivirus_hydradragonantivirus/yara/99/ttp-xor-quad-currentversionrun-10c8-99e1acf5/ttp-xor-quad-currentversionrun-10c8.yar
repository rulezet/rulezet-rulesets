rule TTP_XOR_QUAD_CurrentVersionRun_10c8 {
  strings:
    $key_10c8 = { 43 a7 [2] 67 a9 [2] 4c 85 [2] 62 a7 [2] 76 bc [2] 79 a6 [2] 67 bb [2] 65 ba [2] 7e bc [2] 62 bb [2] 7e 94 }

  condition:
    any of them
}