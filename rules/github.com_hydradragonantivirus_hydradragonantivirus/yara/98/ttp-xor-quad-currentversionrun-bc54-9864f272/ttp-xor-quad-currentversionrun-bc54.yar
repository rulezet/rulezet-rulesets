rule TTP_XOR_QUAD_CurrentVersionRun_bc54 {
  strings:
    $key_bc54 = { ef 3b [2] cb 35 [2] e0 19 [2] ce 3b [2] da 20 [2] d5 3a [2] cb 27 [2] c9 26 [2] d2 20 [2] ce 27 [2] d2 08 }

  condition:
    any of them
}