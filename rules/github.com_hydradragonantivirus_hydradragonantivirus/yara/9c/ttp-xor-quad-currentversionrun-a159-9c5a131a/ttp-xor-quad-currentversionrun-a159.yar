rule TTP_XOR_QUAD_CurrentVersionRun_a159 {
  strings:
    $key_a159 = { f2 36 [2] d6 38 [2] fd 14 [2] d3 36 [2] c7 2d [2] c8 37 [2] d6 2a [2] d4 2b [2] cf 2d [2] d3 2a [2] cf 05 }

  condition:
    any of them
}