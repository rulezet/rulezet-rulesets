rule TTP_XOR_QUAD_CurrentVersionRun_bc5e {
  strings:
    $key_bc5e = { ef 31 [2] cb 3f [2] e0 13 [2] ce 31 [2] da 2a [2] d5 30 [2] cb 2d [2] c9 2c [2] d2 2a [2] ce 2d [2] d2 02 }

  condition:
    any of them
}