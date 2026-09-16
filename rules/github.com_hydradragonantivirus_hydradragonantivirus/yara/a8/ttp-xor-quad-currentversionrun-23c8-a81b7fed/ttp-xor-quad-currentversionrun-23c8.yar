rule TTP_XOR_QUAD_CurrentVersionRun_23c8 {
  strings:
    $key_23c8 = { 70 a7 [2] 54 a9 [2] 7f 85 [2] 51 a7 [2] 45 bc [2] 4a a6 [2] 54 bb [2] 56 ba [2] 4d bc [2] 51 bb [2] 4d 94 }

  condition:
    any of them
}