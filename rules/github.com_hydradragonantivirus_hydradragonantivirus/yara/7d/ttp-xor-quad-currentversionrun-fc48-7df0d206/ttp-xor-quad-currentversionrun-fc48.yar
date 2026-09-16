rule TTP_XOR_QUAD_CurrentVersionRun_fc48 {
  strings:
    $key_fc48 = { af 27 [2] 8b 29 [2] a0 05 [2] 8e 27 [2] 9a 3c [2] 95 26 [2] 8b 3b [2] 89 3a [2] 92 3c [2] 8e 3b [2] 92 14 }

  condition:
    any of them
}