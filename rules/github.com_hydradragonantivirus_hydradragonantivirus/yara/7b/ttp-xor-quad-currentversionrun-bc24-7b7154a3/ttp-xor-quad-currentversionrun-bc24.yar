rule TTP_XOR_QUAD_CurrentVersionRun_bc24 {
  strings:
    $key_bc24 = { ef 4b [2] cb 45 [2] e0 69 [2] ce 4b [2] da 50 [2] d5 4a [2] cb 57 [2] c9 56 [2] d2 50 [2] ce 57 [2] d2 78 }

  condition:
    any of them
}