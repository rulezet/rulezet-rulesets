rule TTP_XOR_QUAD_CurrentVersionRun_fc77 {
  strings:
    $key_fc77 = { af 18 [2] 8b 16 [2] a0 3a [2] 8e 18 [2] 9a 03 [2] 95 19 [2] 8b 04 [2] 89 05 [2] 92 03 [2] 8e 04 [2] 92 2b }

  condition:
    any of them
}