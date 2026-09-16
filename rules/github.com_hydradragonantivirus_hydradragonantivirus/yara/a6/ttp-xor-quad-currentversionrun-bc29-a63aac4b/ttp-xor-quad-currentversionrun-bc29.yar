rule TTP_XOR_QUAD_CurrentVersionRun_bc29 {
  strings:
    $key_bc29 = { ef 46 [2] cb 48 [2] e0 64 [2] ce 46 [2] da 5d [2] d5 47 [2] cb 5a [2] c9 5b [2] d2 5d [2] ce 5a [2] d2 75 }

  condition:
    any of them
}