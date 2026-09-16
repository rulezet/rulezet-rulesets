rule TTP_XOR_QUAD_CurrentVersionRun_bc08 {
  strings:
    $key_bc08 = { ef 67 [2] cb 69 [2] e0 45 [2] ce 67 [2] da 7c [2] d5 66 [2] cb 7b [2] c9 7a [2] d2 7c [2] ce 7b [2] d2 54 }

  condition:
    any of them
}