rule TTP_XOR_QUAD_CurrentVersionRun_bc59 {
  strings:
    $key_bc59 = { ef 36 [2] cb 38 [2] e0 14 [2] ce 36 [2] da 2d [2] d5 37 [2] cb 2a [2] c9 2b [2] d2 2d [2] ce 2a [2] d2 05 }

  condition:
    any of them
}