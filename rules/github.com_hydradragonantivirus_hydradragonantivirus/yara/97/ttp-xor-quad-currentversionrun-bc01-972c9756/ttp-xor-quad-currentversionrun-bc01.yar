rule TTP_XOR_QUAD_CurrentVersionRun_bc01 {
  strings:
    $key_bc01 = { ef 6e [2] cb 60 [2] e0 4c [2] ce 6e [2] da 75 [2] d5 6f [2] cb 72 [2] c9 73 [2] d2 75 [2] ce 72 [2] d2 5d }

  condition:
    any of them
}