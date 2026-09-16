rule TTP_XOR_QUAD_CurrentVersionRun_fc67 {
  strings:
    $key_fc67 = { af 08 [2] 8b 06 [2] a0 2a [2] 8e 08 [2] 9a 13 [2] 95 09 [2] 8b 14 [2] 89 15 [2] 92 13 [2] 8e 14 [2] 92 3b }

  condition:
    any of them
}