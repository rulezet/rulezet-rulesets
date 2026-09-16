rule TTP_XOR_QUAD_CurrentVersionRun_a659 {
  strings:
    $key_a659 = { f5 36 [2] d1 38 [2] fa 14 [2] d4 36 [2] c0 2d [2] cf 37 [2] d1 2a [2] d3 2b [2] c8 2d [2] d4 2a [2] c8 05 }

  condition:
    any of them
}