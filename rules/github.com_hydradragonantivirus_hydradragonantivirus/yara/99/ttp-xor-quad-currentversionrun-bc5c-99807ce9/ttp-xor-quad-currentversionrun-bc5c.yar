rule TTP_XOR_QUAD_CurrentVersionRun_bc5c {
  strings:
    $key_bc5c = { ef 33 [2] cb 3d [2] e0 11 [2] ce 33 [2] da 28 [2] d5 32 [2] cb 2f [2] c9 2e [2] d2 28 [2] ce 2f [2] d2 00 }

  condition:
    any of them
}