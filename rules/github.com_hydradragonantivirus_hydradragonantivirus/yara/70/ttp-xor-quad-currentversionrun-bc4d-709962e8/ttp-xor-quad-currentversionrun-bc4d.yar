rule TTP_XOR_QUAD_CurrentVersionRun_bc4d {
  strings:
    $key_bc4d = { ef 22 [2] cb 2c [2] e0 00 [2] ce 22 [2] da 39 [2] d5 23 [2] cb 3e [2] c9 3f [2] d2 39 [2] ce 3e [2] d2 11 }

  condition:
    any of them
}