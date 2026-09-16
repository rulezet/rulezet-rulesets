rule TTP_XOR_QUAD_CurrentVersionRun_bc35 {
  strings:
    $key_bc35 = { ef 5a [2] cb 54 [2] e0 78 [2] ce 5a [2] da 41 [2] d5 5b [2] cb 46 [2] c9 47 [2] d2 41 [2] ce 46 [2] d2 69 }

  condition:
    any of them
}