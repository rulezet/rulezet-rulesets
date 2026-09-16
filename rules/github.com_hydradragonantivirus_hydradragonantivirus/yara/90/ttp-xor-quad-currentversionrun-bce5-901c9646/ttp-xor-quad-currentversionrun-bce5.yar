rule TTP_XOR_QUAD_CurrentVersionRun_bce5 {
  strings:
    $key_bce5 = { ef 8a [2] cb 84 [2] e0 a8 [2] ce 8a [2] da 91 [2] d5 8b [2] cb 96 [2] c9 97 [2] d2 91 [2] ce 96 [2] d2 b9 }

  condition:
    any of them
}