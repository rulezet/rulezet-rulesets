rule TTP_XOR_QUAD_CurrentVersionRun_bc2f {
  strings:
    $key_bc2f = { ef 40 [2] cb 4e [2] e0 62 [2] ce 40 [2] da 5b [2] d5 41 [2] cb 5c [2] c9 5d [2] d2 5b [2] ce 5c [2] d2 73 }

  condition:
    any of them
}