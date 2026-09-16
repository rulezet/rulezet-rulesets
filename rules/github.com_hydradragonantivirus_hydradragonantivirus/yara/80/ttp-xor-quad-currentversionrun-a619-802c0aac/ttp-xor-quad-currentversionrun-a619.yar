rule TTP_XOR_QUAD_CurrentVersionRun_a619 {
  strings:
    $key_a619 = { f5 76 [2] d1 78 [2] fa 54 [2] d4 76 [2] c0 6d [2] cf 77 [2] d1 6a [2] d3 6b [2] c8 6d [2] d4 6a [2] c8 45 }

  condition:
    any of them
}