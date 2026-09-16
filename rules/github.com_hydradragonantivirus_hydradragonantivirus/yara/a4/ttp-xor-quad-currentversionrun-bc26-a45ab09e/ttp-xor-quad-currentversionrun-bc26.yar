rule TTP_XOR_QUAD_CurrentVersionRun_bc26 {
  strings:
    $key_bc26 = { ef 49 [2] cb 47 [2] e0 6b [2] ce 49 [2] da 52 [2] d5 48 [2] cb 55 [2] c9 54 [2] d2 52 [2] ce 55 [2] d2 7a }

  condition:
    any of them
}