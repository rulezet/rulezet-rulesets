rule TTP_XOR_QUAD_CurrentVersionRun_bcff {
  strings:
    $key_bcff = { ef 90 [2] cb 9e [2] e0 b2 [2] ce 90 [2] da 8b [2] d5 91 [2] cb 8c [2] c9 8d [2] d2 8b [2] ce 8c [2] d2 a3 }

  condition:
    any of them
}