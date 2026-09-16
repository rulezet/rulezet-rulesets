rule TTP_XOR_QUAD_CurrentVersionRun_a609 {
  strings:
    $key_a609 = { f5 66 [2] d1 68 [2] fa 44 [2] d4 66 [2] c0 7d [2] cf 67 [2] d1 7a [2] d3 7b [2] c8 7d [2] d4 7a [2] c8 55 }

  condition:
    any of them
}