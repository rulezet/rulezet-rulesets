rule TTP_XOR_QUAD_CurrentVersionRun_bc61 {
  strings:
    $key_bc61 = { ef 0e [2] cb 00 [2] e0 2c [2] ce 0e [2] da 15 [2] d5 0f [2] cb 12 [2] c9 13 [2] d2 15 [2] ce 12 [2] d2 3d }

  condition:
    any of them
}