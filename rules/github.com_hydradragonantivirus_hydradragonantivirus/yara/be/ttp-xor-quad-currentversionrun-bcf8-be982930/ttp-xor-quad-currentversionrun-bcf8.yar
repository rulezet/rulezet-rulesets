rule TTP_XOR_QUAD_CurrentVersionRun_bcf8 {
  strings:
    $key_bcf8 = { ef 97 [2] cb 99 [2] e0 b5 [2] ce 97 [2] da 8c [2] d5 96 [2] cb 8b [2] c9 8a [2] d2 8c [2] ce 8b [2] d2 a4 }

  condition:
    any of them
}