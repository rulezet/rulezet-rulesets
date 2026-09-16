rule TTP_XOR_QUAD_CurrentVersionRun_bc3c {
  strings:
    $key_bc3c = { ef 53 [2] cb 5d [2] e0 71 [2] ce 53 [2] da 48 [2] d5 52 [2] cb 4f [2] c9 4e [2] d2 48 [2] ce 4f [2] d2 60 }

  condition:
    any of them
}