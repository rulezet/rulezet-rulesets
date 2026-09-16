rule TTP_XOR_QUAD_CurrentVersionRun_bc1d {
  strings:
    $key_bc1d = { ef 72 [2] cb 7c [2] e0 50 [2] ce 72 [2] da 69 [2] d5 73 [2] cb 6e [2] c9 6f [2] d2 69 [2] ce 6e [2] d2 41 }

  condition:
    any of them
}