rule TTP_XOR_QUAD_CurrentVersionRun_fc66 {
  strings:
    $key_fc66 = { af 09 [2] 8b 07 [2] a0 2b [2] 8e 09 [2] 9a 12 [2] 95 08 [2] 8b 15 [2] 89 14 [2] 92 12 [2] 8e 15 [2] 92 3a }

  condition:
    any of them
}