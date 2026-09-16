rule TTP_XOR_QUAD_CurrentVersionRun_bcf9 {
  strings:
    $key_bcf9 = { ef 96 [2] cb 98 [2] e0 b4 [2] ce 96 [2] da 8d [2] d5 97 [2] cb 8a [2] c9 8b [2] d2 8d [2] ce 8a [2] d2 a5 }

  condition:
    any of them
}