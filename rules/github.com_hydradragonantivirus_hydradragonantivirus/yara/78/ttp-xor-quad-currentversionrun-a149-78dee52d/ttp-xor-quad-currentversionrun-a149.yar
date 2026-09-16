rule TTP_XOR_QUAD_CurrentVersionRun_a149 {
  strings:
    $key_a149 = { f2 26 [2] d6 28 [2] fd 04 [2] d3 26 [2] c7 3d [2] c8 27 [2] d6 3a [2] d4 3b [2] cf 3d [2] d3 3a [2] cf 15 }

  condition:
    any of them
}