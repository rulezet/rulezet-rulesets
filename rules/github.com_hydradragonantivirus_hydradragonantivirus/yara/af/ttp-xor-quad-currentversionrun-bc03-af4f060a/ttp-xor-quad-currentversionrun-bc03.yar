rule TTP_XOR_QUAD_CurrentVersionRun_bc03 {
  strings:
    $key_bc03 = { ef 6c [2] cb 62 [2] e0 4e [2] ce 6c [2] da 77 [2] d5 6d [2] cb 70 [2] c9 71 [2] d2 77 [2] ce 70 [2] d2 5f }

  condition:
    any of them
}