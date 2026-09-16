rule TTP_XOR_QUAD_CurrentVersionRun_15c8 {
  strings:
    $key_15c8 = { 46 a7 [2] 62 a9 [2] 49 85 [2] 67 a7 [2] 73 bc [2] 7c a6 [2] 62 bb [2] 60 ba [2] 7b bc [2] 67 bb [2] 7b 94 }

  condition:
    any of them
}