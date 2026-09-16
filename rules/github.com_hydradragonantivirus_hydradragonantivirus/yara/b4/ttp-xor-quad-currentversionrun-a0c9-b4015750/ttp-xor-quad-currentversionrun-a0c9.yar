rule TTP_XOR_QUAD_CurrentVersionRun_a0c9 {
  strings:
    $key_a0c9 = { f3 a6 [2] d7 a8 [2] fc 84 [2] d2 a6 [2] c6 bd [2] c9 a7 [2] d7 ba [2] d5 bb [2] ce bd [2] d2 ba [2] ce 95 }

  condition:
    any of them
}