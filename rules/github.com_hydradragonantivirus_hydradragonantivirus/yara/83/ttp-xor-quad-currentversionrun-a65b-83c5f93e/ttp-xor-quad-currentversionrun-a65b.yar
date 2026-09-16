rule TTP_XOR_QUAD_CurrentVersionRun_a65b {
  strings:
    $key_a65b = { f5 34 [2] d1 3a [2] fa 16 [2] d4 34 [2] c0 2f [2] cf 35 [2] d1 28 [2] d3 29 [2] c8 2f [2] d4 28 [2] c8 07 }

  condition:
    any of them
}