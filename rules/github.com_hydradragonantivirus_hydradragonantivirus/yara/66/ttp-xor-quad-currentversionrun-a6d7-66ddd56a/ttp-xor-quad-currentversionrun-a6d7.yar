rule TTP_XOR_QUAD_CurrentVersionRun_a6d7 {
  strings:
    $key_a6d7 = { f5 b8 [2] d1 b6 [2] fa 9a [2] d4 b8 [2] c0 a3 [2] cf b9 [2] d1 a4 [2] d3 a5 [2] c8 a3 [2] d4 a4 [2] c8 8b }

  condition:
    any of them
}