rule TTP_XOR_QUAD_CurrentVersionRun_bcfa {
  strings:
    $key_bcfa = { ef 95 [2] cb 9b [2] e0 b7 [2] ce 95 [2] da 8e [2] d5 94 [2] cb 89 [2] c9 88 [2] d2 8e [2] ce 89 [2] d2 a6 }

  condition:
    any of them
}