rule TTP_XOR_QUAD_CurrentVersionRun_bc1c {
  strings:
    $key_bc1c = { ef 73 [2] cb 7d [2] e0 51 [2] ce 73 [2] da 68 [2] d5 72 [2] cb 6f [2] c9 6e [2] d2 68 [2] ce 6f [2] d2 40 }

  condition:
    any of them
}