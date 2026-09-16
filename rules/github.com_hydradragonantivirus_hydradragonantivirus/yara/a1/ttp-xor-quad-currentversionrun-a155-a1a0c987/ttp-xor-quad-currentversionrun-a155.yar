rule TTP_XOR_QUAD_CurrentVersionRun_a155 {
  strings:
    $key_a155 = { f2 3a [2] d6 34 [2] fd 18 [2] d3 3a [2] c7 21 [2] c8 3b [2] d6 26 [2] d4 27 [2] cf 21 [2] d3 26 [2] cf 09 }

  condition:
    any of them
}