rule TTP_XOR_QUAD_CurrentVersionRun_a124 {
  strings:
    $key_a124 = { f2 4b [2] d6 45 [2] fd 69 [2] d3 4b [2] c7 50 [2] c8 4a [2] d6 57 [2] d4 56 [2] cf 50 [2] d3 57 [2] cf 78 }

  condition:
    any of them
}