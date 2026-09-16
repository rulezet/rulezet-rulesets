rule TTP_XOR_QUAD_CurrentVersionRun_bc36 {
  strings:
    $key_bc36 = { ef 59 [2] cb 57 [2] e0 7b [2] ce 59 [2] da 42 [2] d5 58 [2] cb 45 [2] c9 44 [2] d2 42 [2] ce 45 [2] d2 6a }

  condition:
    any of them
}