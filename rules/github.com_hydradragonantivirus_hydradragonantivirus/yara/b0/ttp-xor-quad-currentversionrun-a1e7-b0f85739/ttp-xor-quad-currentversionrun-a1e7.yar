rule TTP_XOR_QUAD_CurrentVersionRun_a1e7 {
  strings:
    $key_a1e7 = { f2 88 [2] d6 86 [2] fd aa [2] d3 88 [2] c7 93 [2] c8 89 [2] d6 94 [2] d4 95 [2] cf 93 [2] d3 94 [2] cf bb }

  condition:
    any of them
}