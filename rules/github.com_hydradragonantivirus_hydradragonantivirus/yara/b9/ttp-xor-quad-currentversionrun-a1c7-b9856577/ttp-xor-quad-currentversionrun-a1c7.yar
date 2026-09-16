rule TTP_XOR_QUAD_CurrentVersionRun_a1c7 {
  strings:
    $key_a1c7 = { f2 a8 [2] d6 a6 [2] fd 8a [2] d3 a8 [2] c7 b3 [2] c8 a9 [2] d6 b4 [2] d4 b5 [2] cf b3 [2] d3 b4 [2] cf 9b }

  condition:
    any of them
}