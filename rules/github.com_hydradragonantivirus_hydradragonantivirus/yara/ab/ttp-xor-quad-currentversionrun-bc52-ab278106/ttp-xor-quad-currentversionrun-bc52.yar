rule TTP_XOR_QUAD_CurrentVersionRun_bc52 {
  strings:
    $key_bc52 = { ef 3d [2] cb 33 [2] e0 1f [2] ce 3d [2] da 26 [2] d5 3c [2] cb 21 [2] c9 20 [2] d2 26 [2] ce 21 [2] d2 0e }

  condition:
    any of them
}