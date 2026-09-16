rule TTP_XOR_QUAD_CurrentVersionRun_bc7b {
  strings:
    $key_bc7b = { ef 14 [2] cb 1a [2] e0 36 [2] ce 14 [2] da 0f [2] d5 15 [2] cb 08 [2] c9 09 [2] d2 0f [2] ce 08 [2] d2 27 }

  condition:
    any of them
}