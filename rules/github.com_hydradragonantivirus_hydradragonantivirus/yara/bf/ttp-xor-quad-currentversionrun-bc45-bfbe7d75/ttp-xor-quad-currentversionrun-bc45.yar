rule TTP_XOR_QUAD_CurrentVersionRun_bc45 {
  strings:
    $key_bc45 = { ef 2a [2] cb 24 [2] e0 08 [2] ce 2a [2] da 31 [2] d5 2b [2] cb 36 [2] c9 37 [2] d2 31 [2] ce 36 [2] d2 19 }

  condition:
    any of them
}