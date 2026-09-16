rule TTP_XOR_QUAD_CurrentVersionRun_a627 {
  strings:
    $key_a627 = { f5 48 [2] d1 46 [2] fa 6a [2] d4 48 [2] c0 53 [2] cf 49 [2] d1 54 [2] d3 55 [2] c8 53 [2] d4 54 [2] c8 7b }

  condition:
    any of them
}