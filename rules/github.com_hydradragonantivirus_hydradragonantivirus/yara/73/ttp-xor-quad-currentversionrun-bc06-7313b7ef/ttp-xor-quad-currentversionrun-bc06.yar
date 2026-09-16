rule TTP_XOR_QUAD_CurrentVersionRun_bc06 {
  strings:
    $key_bc06 = { ef 69 [2] cb 67 [2] e0 4b [2] ce 69 [2] da 72 [2] d5 68 [2] cb 75 [2] c9 74 [2] d2 72 [2] ce 75 [2] d2 5a }

  condition:
    any of them
}