rule TTP_XOR_QUAD_CurrentVersionRun_a6d6 {
  strings:
    $key_a6d6 = { f5 b9 [2] d1 b7 [2] fa 9b [2] d4 b9 [2] c0 a2 [2] cf b8 [2] d1 a5 [2] d3 a4 [2] c8 a2 [2] d4 a5 [2] c8 8a }

  condition:
    any of them
}