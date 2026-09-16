rule TTP_XOR_QUAD_CurrentVersionRun_fc69 {
  strings:
    $key_fc69 = { af 06 [2] 8b 08 [2] a0 24 [2] 8e 06 [2] 9a 1d [2] 95 07 [2] 8b 1a [2] 89 1b [2] 92 1d [2] 8e 1a [2] 92 35 }

  condition:
    any of them
}