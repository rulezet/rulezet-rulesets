rule TTP_XOR_QUAD_CurrentVersionRun_a607 {
  strings:
    $key_a607 = { f5 68 [2] d1 66 [2] fa 4a [2] d4 68 [2] c0 73 [2] cf 69 [2] d1 74 [2] d3 75 [2] c8 73 [2] d4 74 [2] c8 5b }

  condition:
    any of them
}