rule TTP_XOR_QUAD_CurrentVersionRun_bc40 {
  strings:
    $key_bc40 = { ef 2f [2] cb 21 [2] e0 0d [2] ce 2f [2] da 34 [2] d5 2e [2] cb 33 [2] c9 32 [2] d2 34 [2] ce 33 [2] d2 1c }

  condition:
    any of them
}