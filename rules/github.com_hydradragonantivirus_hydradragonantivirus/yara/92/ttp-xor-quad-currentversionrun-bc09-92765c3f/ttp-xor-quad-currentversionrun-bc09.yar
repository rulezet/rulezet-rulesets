rule TTP_XOR_QUAD_CurrentVersionRun_bc09 {
  strings:
    $key_bc09 = { ef 66 [2] cb 68 [2] e0 44 [2] ce 66 [2] da 7d [2] d5 67 [2] cb 7a [2] c9 7b [2] d2 7d [2] ce 7a [2] d2 55 }

  condition:
    any of them
}