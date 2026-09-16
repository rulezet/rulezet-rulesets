rule TTP_XOR_QUAD_CurrentVersionRun_a656 {
  strings:
    $key_a656 = { f5 39 [2] d1 37 [2] fa 1b [2] d4 39 [2] c0 22 [2] cf 38 [2] d1 25 [2] d3 24 [2] c8 22 [2] d4 25 [2] c8 0a }

  condition:
    any of them
}