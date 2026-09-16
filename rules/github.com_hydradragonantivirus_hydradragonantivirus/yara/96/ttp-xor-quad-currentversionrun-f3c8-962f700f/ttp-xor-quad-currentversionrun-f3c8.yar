rule TTP_XOR_QUAD_CurrentVersionRun_f3c8 {
  strings:
    $key_f3c8 = { a0 a7 [2] 84 a9 [2] af 85 [2] 81 a7 [2] 95 bc [2] 9a a6 [2] 84 bb [2] 86 ba [2] 9d bc [2] 81 bb [2] 9d 94 }

  condition:
    any of them
}