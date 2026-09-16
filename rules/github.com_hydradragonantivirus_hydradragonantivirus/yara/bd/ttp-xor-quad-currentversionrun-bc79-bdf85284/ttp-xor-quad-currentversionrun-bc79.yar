rule TTP_XOR_QUAD_CurrentVersionRun_bc79 {
  strings:
    $key_bc79 = { ef 16 [2] cb 18 [2] e0 34 [2] ce 16 [2] da 0d [2] d5 17 [2] cb 0a [2] c9 0b [2] d2 0d [2] ce 0a [2] d2 25 }

  condition:
    any of them
}