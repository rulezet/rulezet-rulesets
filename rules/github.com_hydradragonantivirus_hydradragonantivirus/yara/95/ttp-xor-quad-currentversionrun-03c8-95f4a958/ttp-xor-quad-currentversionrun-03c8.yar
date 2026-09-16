rule TTP_XOR_QUAD_CurrentVersionRun_03c8 {
  strings:
    $key_03c8 = { 50 a7 [2] 74 a9 [2] 5f 85 [2] 71 a7 [2] 65 bc [2] 6a a6 [2] 74 bb [2] 76 ba [2] 6d bc [2] 71 bb [2] 6d 94 }

  condition:
    any of them
}