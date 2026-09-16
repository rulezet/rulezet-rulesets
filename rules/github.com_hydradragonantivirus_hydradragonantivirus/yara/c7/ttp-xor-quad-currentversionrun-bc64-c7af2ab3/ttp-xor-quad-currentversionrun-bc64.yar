rule TTP_XOR_QUAD_CurrentVersionRun_bc64 {
  strings:
    $key_bc64 = { ef 0b [2] cb 05 [2] e0 29 [2] ce 0b [2] da 10 [2] d5 0a [2] cb 17 [2] c9 16 [2] d2 10 [2] ce 17 [2] d2 38 }

  condition:
    any of them
}