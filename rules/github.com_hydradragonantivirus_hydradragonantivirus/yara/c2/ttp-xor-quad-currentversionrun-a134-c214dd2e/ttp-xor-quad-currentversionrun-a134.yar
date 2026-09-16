rule TTP_XOR_QUAD_CurrentVersionRun_a134 {
  strings:
    $key_a134 = { f2 5b [2] d6 55 [2] fd 79 [2] d3 5b [2] c7 40 [2] c8 5a [2] d6 47 [2] d4 46 [2] cf 40 [2] d3 47 [2] cf 68 }

  condition:
    any of them
}