rule TTP_XOR_QUAD_CurrentVersionRun_bc71 {
  strings:
    $key_bc71 = { ef 1e [2] cb 10 [2] e0 3c [2] ce 1e [2] da 05 [2] d5 1f [2] cb 02 [2] c9 03 [2] d2 05 [2] ce 02 [2] d2 2d }

  condition:
    any of them
}