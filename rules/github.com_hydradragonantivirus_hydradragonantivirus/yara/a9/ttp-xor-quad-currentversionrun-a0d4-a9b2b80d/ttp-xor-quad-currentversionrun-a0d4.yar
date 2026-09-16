rule TTP_XOR_QUAD_CurrentVersionRun_a0d4 {
  strings:
    $key_a0d4 = { f3 bb [2] d7 b5 [2] fc 99 [2] d2 bb [2] c6 a0 [2] c9 ba [2] d7 a7 [2] d5 a6 [2] ce a0 [2] d2 a7 [2] ce 88 }

  condition:
    any of them
}