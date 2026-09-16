rule TTP_XOR_QUAD_CurrentVersionRun_bc38 {
  strings:
    $key_bc38 = { ef 57 [2] cb 59 [2] e0 75 [2] ce 57 [2] da 4c [2] d5 56 [2] cb 4b [2] c9 4a [2] d2 4c [2] ce 4b [2] d2 64 }

  condition:
    any of them
}