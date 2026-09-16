rule TTP_XOR_QUAD_CurrentVersionRun_bc2d {
  strings:
    $key_bc2d = { ef 42 [2] cb 4c [2] e0 60 [2] ce 42 [2] da 59 [2] d5 43 [2] cb 5e [2] c9 5f [2] d2 59 [2] ce 5e [2] d2 71 }

  condition:
    any of them
}