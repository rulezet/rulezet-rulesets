rule TTP_XOR_QUAD_CurrentVersionRun_a1e8 {
  strings:
    $key_a1e8 = { f2 87 [2] d6 89 [2] fd a5 [2] d3 87 [2] c7 9c [2] c8 86 [2] d6 9b [2] d4 9a [2] cf 9c [2] d3 9b [2] cf b4 }

  condition:
    any of them
}