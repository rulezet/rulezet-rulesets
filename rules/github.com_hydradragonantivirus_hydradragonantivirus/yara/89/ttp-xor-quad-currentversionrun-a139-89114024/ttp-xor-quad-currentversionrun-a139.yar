rule TTP_XOR_QUAD_CurrentVersionRun_a139 {
  strings:
    $key_a139 = { f2 56 [2] d6 58 [2] fd 74 [2] d3 56 [2] c7 4d [2] c8 57 [2] d6 4a [2] d4 4b [2] cf 4d [2] d3 4a [2] cf 65 }

  condition:
    any of them
}