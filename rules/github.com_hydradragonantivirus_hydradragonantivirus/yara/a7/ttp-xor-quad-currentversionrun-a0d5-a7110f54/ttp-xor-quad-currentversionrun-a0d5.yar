rule TTP_XOR_QUAD_CurrentVersionRun_a0d5 {
  strings:
    $key_a0d5 = { f3 ba [2] d7 b4 [2] fc 98 [2] d2 ba [2] c6 a1 [2] c9 bb [2] d7 a6 [2] d5 a7 [2] ce a1 [2] d2 a6 [2] ce 89 }

  condition:
    any of them
}