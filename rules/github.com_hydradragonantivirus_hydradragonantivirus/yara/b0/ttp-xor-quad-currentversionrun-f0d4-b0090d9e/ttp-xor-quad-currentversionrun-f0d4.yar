rule TTP_XOR_QUAD_CurrentVersionRun_f0d4 {
  strings:
    $key_f0d4 = { a3 bb [2] 87 b5 [2] ac 99 [2] 82 bb [2] 96 a0 [2] 99 ba [2] 87 a7 [2] 85 a6 [2] 9e a0 [2] 82 a7 [2] 9e 88 }

  condition:
    any of them
}