rule TTP_XOR_QUAD_CurrentVersionRun_bc34 {
  strings:
    $key_bc34 = { ef 5b [2] cb 55 [2] e0 79 [2] ce 5b [2] da 40 [2] d5 5a [2] cb 47 [2] c9 46 [2] d2 40 [2] ce 47 [2] d2 68 }

  condition:
    any of them
}