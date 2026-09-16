rule TTP_XOR_QUAD_CurrentVersionRun_a674 {
  strings:
    $key_a674 = { f5 1b [2] d1 15 [2] fa 39 [2] d4 1b [2] c0 00 [2] cf 1a [2] d1 07 [2] d3 06 [2] c8 00 [2] d4 07 [2] c8 28 }

  condition:
    any of them
}