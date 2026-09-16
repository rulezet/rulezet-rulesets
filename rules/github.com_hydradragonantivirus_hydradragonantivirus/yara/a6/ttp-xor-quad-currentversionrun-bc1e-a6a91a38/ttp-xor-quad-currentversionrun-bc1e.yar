rule TTP_XOR_QUAD_CurrentVersionRun_bc1e {
  strings:
    $key_bc1e = { ef 71 [2] cb 7f [2] e0 53 [2] ce 71 [2] da 6a [2] d5 70 [2] cb 6d [2] c9 6c [2] d2 6a [2] ce 6d [2] d2 42 }

  condition:
    any of them
}