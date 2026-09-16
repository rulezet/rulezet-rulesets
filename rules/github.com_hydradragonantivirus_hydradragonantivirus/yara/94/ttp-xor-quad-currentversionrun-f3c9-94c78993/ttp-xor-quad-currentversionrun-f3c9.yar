rule TTP_XOR_QUAD_CurrentVersionRun_f3c9 {
  strings:
    $key_f3c9 = { a0 a6 [2] 84 a8 [2] af 84 [2] 81 a6 [2] 95 bd [2] 9a a7 [2] 84 ba [2] 86 bb [2] 9d bd [2] 81 ba [2] 9d 95 }

  condition:
    any of them
}