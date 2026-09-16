rule TTP_XOR_QUAD_CurrentVersionRun_bc42 {
  strings:
    $key_bc42 = { ef 2d [2] cb 23 [2] e0 0f [2] ce 2d [2] da 36 [2] d5 2c [2] cb 31 [2] c9 30 [2] d2 36 [2] ce 31 [2] d2 1e }

  condition:
    any of them
}