rule TTP_XOR_QUAD_CurrentVersionRun_bc2c {
  strings:
    $key_bc2c = { ef 43 [2] cb 4d [2] e0 61 [2] ce 43 [2] da 58 [2] d5 42 [2] cb 5f [2] c9 5e [2] d2 58 [2] ce 5f [2] d2 70 }

  condition:
    any of them
}