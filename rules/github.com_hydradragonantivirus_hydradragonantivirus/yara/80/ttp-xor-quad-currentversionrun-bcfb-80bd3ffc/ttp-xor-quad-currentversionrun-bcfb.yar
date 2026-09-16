rule TTP_XOR_QUAD_CurrentVersionRun_bcfb {
  strings:
    $key_bcfb = { ef 94 [2] cb 9a [2] e0 b6 [2] ce 94 [2] da 8f [2] d5 95 [2] cb 88 [2] c9 89 [2] d2 8f [2] ce 88 [2] d2 a7 }

  condition:
    any of them
}