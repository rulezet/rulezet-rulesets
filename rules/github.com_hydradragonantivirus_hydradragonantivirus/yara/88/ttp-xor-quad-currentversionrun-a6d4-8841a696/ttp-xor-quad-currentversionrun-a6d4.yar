rule TTP_XOR_QUAD_CurrentVersionRun_a6d4 {
  strings:
    $key_a6d4 = { f5 bb [2] d1 b5 [2] fa 99 [2] d4 bb [2] c0 a0 [2] cf ba [2] d1 a7 [2] d3 a6 [2] c8 a0 [2] d4 a7 [2] c8 88 }

  condition:
    any of them
}