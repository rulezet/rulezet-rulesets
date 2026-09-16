rule TTP_XOR_QUAD_CurrentVersionRun_fc6b {
  strings:
    $key_fc6b = { af 04 [2] 8b 0a [2] a0 26 [2] 8e 04 [2] 9a 1f [2] 95 05 [2] 8b 18 [2] 89 19 [2] 92 1f [2] 8e 18 [2] 92 37 }

  condition:
    any of them
}