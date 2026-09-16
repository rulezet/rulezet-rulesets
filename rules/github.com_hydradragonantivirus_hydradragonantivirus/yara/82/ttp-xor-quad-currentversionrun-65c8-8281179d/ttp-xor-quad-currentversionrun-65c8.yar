rule TTP_XOR_QUAD_CurrentVersionRun_65c8 {
  strings:
    $key_65c8 = { 36 a7 [2] 12 a9 [2] 39 85 [2] 17 a7 [2] 03 bc [2] 0c a6 [2] 12 bb [2] 10 ba [2] 0b bc [2] 17 bb [2] 0b 94 }

  condition:
    any of them
}