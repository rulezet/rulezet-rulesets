rule TTP_XOR_QUAD_CurrentVersionRun_bc73 {
  strings:
    $key_bc73 = { ef 1c [2] cb 12 [2] e0 3e [2] ce 1c [2] da 07 [2] d5 1d [2] cb 00 [2] c9 01 [2] d2 07 [2] ce 00 [2] d2 2f }

  condition:
    any of them
}