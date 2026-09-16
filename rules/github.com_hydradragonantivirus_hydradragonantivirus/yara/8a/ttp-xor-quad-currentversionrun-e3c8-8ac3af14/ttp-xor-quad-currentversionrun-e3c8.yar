rule TTP_XOR_QUAD_CurrentVersionRun_e3c8 {
  strings:
    $key_e3c8 = { b0 a7 [2] 94 a9 [2] bf 85 [2] 91 a7 [2] 85 bc [2] 8a a6 [2] 94 bb [2] 96 ba [2] 8d bc [2] 91 bb [2] 8d 94 }

  condition:
    any of them
}