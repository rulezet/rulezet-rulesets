rule TTP_XOR_QUAD_CurrentVersionRun_bc6f {
  strings:
    $key_bc6f = { ef 00 [2] cb 0e [2] e0 22 [2] ce 00 [2] da 1b [2] d5 01 [2] cb 1c [2] c9 1d [2] d2 1b [2] ce 1c [2] d2 33 }

  condition:
    any of them
}