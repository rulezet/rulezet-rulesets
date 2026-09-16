rule TTP_XOR_QUAD_CurrentVersionRun_bc1f {
  strings:
    $key_bc1f = { ef 70 [2] cb 7e [2] e0 52 [2] ce 70 [2] da 6b [2] d5 71 [2] cb 6c [2] c9 6d [2] d2 6b [2] ce 6c [2] d2 43 }

  condition:
    any of them
}