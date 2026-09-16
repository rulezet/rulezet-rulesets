rule TTP_XOR_QUAD_CurrentVersionRun_a1f5 {
  strings:
    $key_a1f5 = { f2 9a [2] d6 94 [2] fd b8 [2] d3 9a [2] c7 81 [2] c8 9b [2] d6 86 [2] d4 87 [2] cf 81 [2] d3 86 [2] cf a9 }

  condition:
    any of them
}