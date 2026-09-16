rule TTP_XOR_QUAD_CurrentVersionRun_bce9 {
  strings:
    $key_bce9 = { ef 86 [2] cb 88 [2] e0 a4 [2] ce 86 [2] da 9d [2] d5 87 [2] cb 9a [2] c9 9b [2] d2 9d [2] ce 9a [2] d2 b5 }

  condition:
    any of them
}