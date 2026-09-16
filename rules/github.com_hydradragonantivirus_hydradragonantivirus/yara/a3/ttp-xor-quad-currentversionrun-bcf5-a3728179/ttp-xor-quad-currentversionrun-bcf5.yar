rule TTP_XOR_QUAD_CurrentVersionRun_bcf5 {
  strings:
    $key_bcf5 = { ef 9a [2] cb 94 [2] e0 b8 [2] ce 9a [2] da 81 [2] d5 9b [2] cb 86 [2] c9 87 [2] d2 81 [2] ce 86 [2] d2 a9 }

  condition:
    any of them
}