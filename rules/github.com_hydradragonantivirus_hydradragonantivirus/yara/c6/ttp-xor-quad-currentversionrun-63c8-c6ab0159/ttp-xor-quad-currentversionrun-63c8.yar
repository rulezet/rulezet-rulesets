rule TTP_XOR_QUAD_CurrentVersionRun_63c8 {
  strings:
    $key_63c8 = { 30 a7 [2] 14 a9 [2] 3f 85 [2] 11 a7 [2] 05 bc [2] 0a a6 [2] 14 bb [2] 16 ba [2] 0d bc [2] 11 bb [2] 0d 94 }

  condition:
    any of them
}