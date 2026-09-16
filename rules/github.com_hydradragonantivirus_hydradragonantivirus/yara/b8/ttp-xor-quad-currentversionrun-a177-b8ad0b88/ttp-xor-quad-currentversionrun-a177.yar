rule TTP_XOR_QUAD_CurrentVersionRun_a177 {
  strings:
    $key_a177 = { f2 18 [2] d6 16 [2] fd 3a [2] d3 18 [2] c7 03 [2] c8 19 [2] d6 04 [2] d4 05 [2] cf 03 [2] d3 04 [2] cf 2b }

  condition:
    any of them
}