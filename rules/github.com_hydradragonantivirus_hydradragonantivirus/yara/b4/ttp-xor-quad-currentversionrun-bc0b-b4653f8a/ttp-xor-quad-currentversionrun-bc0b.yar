rule TTP_XOR_QUAD_CurrentVersionRun_bc0b {
  strings:
    $key_bc0b = { ef 64 [2] cb 6a [2] e0 46 [2] ce 64 [2] da 7f [2] d5 65 [2] cb 78 [2] c9 79 [2] d2 7f [2] ce 78 [2] d2 57 }

  condition:
    any of them
}