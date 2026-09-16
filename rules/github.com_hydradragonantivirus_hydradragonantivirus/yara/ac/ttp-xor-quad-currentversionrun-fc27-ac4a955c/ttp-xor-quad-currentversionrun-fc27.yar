rule TTP_XOR_QUAD_CurrentVersionRun_fc27 {
  strings:
    $key_fc27 = { af 48 [2] 8b 46 [2] a0 6a [2] 8e 48 [2] 9a 53 [2] 95 49 [2] 8b 54 [2] 89 55 [2] 92 53 [2] 8e 54 [2] 92 7b }

  condition:
    any of them
}