rule TTP_XOR_QUAD_CurrentVersionRun_bcea {
  strings:
    $key_bcea = { ef 85 [2] cb 8b [2] e0 a7 [2] ce 85 [2] da 9e [2] d5 84 [2] cb 99 [2] c9 98 [2] d2 9e [2] ce 99 [2] d2 b6 }

  condition:
    any of them
}