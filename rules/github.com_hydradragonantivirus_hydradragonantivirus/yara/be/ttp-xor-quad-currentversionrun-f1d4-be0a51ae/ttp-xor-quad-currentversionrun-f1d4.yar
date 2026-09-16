rule TTP_XOR_QUAD_CurrentVersionRun_f1d4 {
  strings:
    $key_f1d4 = { a2 bb [2] 86 b5 [2] ad 99 [2] 83 bb [2] 97 a0 [2] 98 ba [2] 86 a7 [2] 84 a6 [2] 9f a0 [2] 83 a7 [2] 9f 88 }

  condition:
    any of them
}