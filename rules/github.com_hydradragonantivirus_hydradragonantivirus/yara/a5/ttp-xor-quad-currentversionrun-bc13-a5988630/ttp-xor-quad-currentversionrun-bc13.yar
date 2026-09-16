rule TTP_XOR_QUAD_CurrentVersionRun_bc13 {
  strings:
    $key_bc13 = { ef 7c [2] cb 72 [2] e0 5e [2] ce 7c [2] da 67 [2] d5 7d [2] cb 60 [2] c9 61 [2] d2 67 [2] ce 60 [2] d2 4f }

  condition:
    any of them
}