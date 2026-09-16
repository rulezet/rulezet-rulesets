rule TTP_XOR_QUAD_CurrentVersionRun_bc55 {
  strings:
    $key_bc55 = { ef 3a [2] cb 34 [2] e0 18 [2] ce 3a [2] da 21 [2] d5 3b [2] cb 26 [2] c9 27 [2] d2 21 [2] ce 26 [2] d2 09 }

  condition:
    any of them
}