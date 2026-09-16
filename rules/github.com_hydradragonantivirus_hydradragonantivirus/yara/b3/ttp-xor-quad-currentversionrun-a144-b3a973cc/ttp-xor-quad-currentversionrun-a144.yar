rule TTP_XOR_QUAD_CurrentVersionRun_a144 {
  strings:
    $key_a144 = { f2 2b [2] d6 25 [2] fd 09 [2] d3 2b [2] c7 30 [2] c8 2a [2] d6 37 [2] d4 36 [2] cf 30 [2] d3 37 [2] cf 18 }

  condition:
    any of them
}