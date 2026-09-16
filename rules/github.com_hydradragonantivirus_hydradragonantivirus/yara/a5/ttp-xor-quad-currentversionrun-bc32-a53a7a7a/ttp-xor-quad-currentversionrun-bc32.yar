rule TTP_XOR_QUAD_CurrentVersionRun_bc32 {
  strings:
    $key_bc32 = { ef 5d [2] cb 53 [2] e0 7f [2] ce 5d [2] da 46 [2] d5 5c [2] cb 41 [2] c9 40 [2] d2 46 [2] ce 41 [2] d2 6e }

  condition:
    any of them
}