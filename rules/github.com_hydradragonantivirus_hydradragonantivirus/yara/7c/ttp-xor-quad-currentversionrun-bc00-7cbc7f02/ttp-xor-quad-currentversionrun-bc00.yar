rule TTP_XOR_QUAD_CurrentVersionRun_bc00 {
  strings:
    $key_bc00 = { ef 6f [2] cb 61 [2] e0 4d [2] ce 6f [2] da 74 [2] d5 6e [2] cb 73 [2] c9 72 [2] d2 74 [2] ce 73 [2] d2 5c }

  condition:
    any of them
}