rule TTP_XOR_QUAD_CurrentVersionRun_bc47 {
  strings:
    $key_bc47 = { ef 28 [2] cb 26 [2] e0 0a [2] ce 28 [2] da 33 [2] d5 29 [2] cb 34 [2] c9 35 [2] d2 33 [2] ce 34 [2] d2 1b }

  condition:
    any of them
}