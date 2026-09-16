rule TTP_XOR_QUAD_CurrentVersionRun_bc2e {
  strings:
    $key_bc2e = { ef 41 [2] cb 4f [2] e0 63 [2] ce 41 [2] da 5a [2] d5 40 [2] cb 5d [2] c9 5c [2] d2 5a [2] ce 5d [2] d2 72 }

  condition:
    any of them
}