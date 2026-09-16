rule TTP_XOR_QUAD_CurrentVersionRun_a6f5 {
  strings:
    $key_a6f5 = { f5 9a [2] d1 94 [2] fa b8 [2] d4 9a [2] c0 81 [2] cf 9b [2] d1 86 [2] d3 87 [2] c8 81 [2] d4 86 [2] c8 a9 }

  condition:
    any of them
}