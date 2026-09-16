rule TTP_XOR_QUAD_CurrentVersionRun_bc66 {
  strings:
    $key_bc66 = { ef 09 [2] cb 07 [2] e0 2b [2] ce 09 [2] da 12 [2] d5 08 [2] cb 15 [2] c9 14 [2] d2 12 [2] ce 15 [2] d2 3a }

  condition:
    any of them
}