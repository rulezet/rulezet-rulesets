rule TTP_XOR_QUAD_CurrentVersionRun_bc4a {
  strings:
    $key_bc4a = { ef 25 [2] cb 2b [2] e0 07 [2] ce 25 [2] da 3e [2] d5 24 [2] cb 39 [2] c9 38 [2] d2 3e [2] ce 39 [2] d2 16 }

  condition:
    any of them
}