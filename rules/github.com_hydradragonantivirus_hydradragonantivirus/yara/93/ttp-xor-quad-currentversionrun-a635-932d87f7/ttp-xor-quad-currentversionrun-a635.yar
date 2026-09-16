rule TTP_XOR_QUAD_CurrentVersionRun_a635 {
  strings:
    $key_a635 = { f5 5a [2] d1 54 [2] fa 78 [2] d4 5a [2] c0 41 [2] cf 5b [2] d1 46 [2] d3 47 [2] c8 41 [2] d4 46 [2] c8 69 }

  condition:
    any of them
}