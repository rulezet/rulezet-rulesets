rule TTP_XOR_QUAD_CurrentVersionRun_a1e9 {
  strings:
    $key_a1e9 = { f2 86 [2] d6 88 [2] fd a4 [2] d3 86 [2] c7 9d [2] c8 87 [2] d6 9a [2] d4 9b [2] cf 9d [2] d3 9a [2] cf b5 }

  condition:
    any of them
}