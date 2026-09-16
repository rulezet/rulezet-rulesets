rule TTP_XOR_QUAD_CurrentVersionRun_bc07 {
  strings:
    $key_bc07 = { ef 68 [2] cb 66 [2] e0 4a [2] ce 68 [2] da 73 [2] d5 69 [2] cb 74 [2] c9 75 [2] d2 73 [2] ce 74 [2] d2 5b }

  condition:
    any of them
}