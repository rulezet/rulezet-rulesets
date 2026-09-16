rule TTP_XOR_QUAD_CurrentVersionRun_bc30 {
  strings:
    $key_bc30 = { ef 5f [2] cb 51 [2] e0 7d [2] ce 5f [2] da 44 [2] d5 5e [2] cb 43 [2] c9 42 [2] d2 44 [2] ce 43 [2] d2 6c }

  condition:
    any of them
}