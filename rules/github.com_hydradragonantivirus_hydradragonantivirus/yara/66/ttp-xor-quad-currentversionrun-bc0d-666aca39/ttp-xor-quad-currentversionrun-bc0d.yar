rule TTP_XOR_QUAD_CurrentVersionRun_bc0d {
  strings:
    $key_bc0d = { ef 62 [2] cb 6c [2] e0 40 [2] ce 62 [2] da 79 [2] d5 63 [2] cb 7e [2] c9 7f [2] d2 79 [2] ce 7e [2] d2 51 }

  condition:
    any of them
}