rule TTP_XOR_QUAD_CurrentVersionRun_bc1b {
  strings:
    $key_bc1b = { ef 74 [2] cb 7a [2] e0 56 [2] ce 74 [2] da 6f [2] d5 75 [2] cb 68 [2] c9 69 [2] d2 6f [2] ce 68 [2] d2 47 }

  condition:
    any of them
}