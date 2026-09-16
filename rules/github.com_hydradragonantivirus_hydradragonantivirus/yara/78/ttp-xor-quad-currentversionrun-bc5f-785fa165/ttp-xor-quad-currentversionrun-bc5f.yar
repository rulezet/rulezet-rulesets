rule TTP_XOR_QUAD_CurrentVersionRun_bc5f {
  strings:
    $key_bc5f = { ef 30 [2] cb 3e [2] e0 12 [2] ce 30 [2] da 2b [2] d5 31 [2] cb 2c [2] c9 2d [2] d2 2b [2] ce 2c [2] d2 03 }

  condition:
    any of them
}