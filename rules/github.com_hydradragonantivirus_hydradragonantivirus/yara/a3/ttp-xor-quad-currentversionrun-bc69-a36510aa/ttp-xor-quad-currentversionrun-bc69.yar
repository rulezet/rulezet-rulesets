rule TTP_XOR_QUAD_CurrentVersionRun_bc69 {
  strings:
    $key_bc69 = { ef 06 [2] cb 08 [2] e0 24 [2] ce 06 [2] da 1d [2] d5 07 [2] cb 1a [2] c9 1b [2] d2 1d [2] ce 1a [2] d2 35 }

  condition:
    any of them
}