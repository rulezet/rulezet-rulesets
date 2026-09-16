rule TTP_XOR_QUAD_CurrentVersionRun_fc65 {
  strings:
    $key_fc65 = { af 0a [2] 8b 04 [2] a0 28 [2] 8e 0a [2] 9a 11 [2] 95 0b [2] 8b 16 [2] 89 17 [2] 92 11 [2] 8e 16 [2] 92 39 }

  condition:
    any of them
}