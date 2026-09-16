rule TTP_XOR_QUAD_CurrentVersionRun_a6c7 {
  strings:
    $key_a6c7 = { f5 a8 [2] d1 a6 [2] fa 8a [2] d4 a8 [2] c0 b3 [2] cf a9 [2] d1 b4 [2] d3 b5 [2] c8 b3 [2] d4 b4 [2] c8 9b }

  condition:
    any of them
}