rule TTP_XOR_QUAD_CurrentVersionRun_a1d4 {
  strings:
    $key_a1d4 = { f2 bb [2] d6 b5 [2] fd 99 [2] d3 bb [2] c7 a0 [2] c8 ba [2] d6 a7 [2] d4 a6 [2] cf a0 [2] d3 a7 [2] cf 88 }

  condition:
    any of them
}