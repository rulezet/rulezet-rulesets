rule TTP_XOR_QUAD_CurrentVersionRun_bc25 {
  strings:
    $key_bc25 = { ef 4a [2] cb 44 [2] e0 68 [2] ce 4a [2] da 51 [2] d5 4b [2] cb 56 [2] c9 57 [2] d2 51 [2] ce 56 [2] d2 79 }

  condition:
    any of them
}