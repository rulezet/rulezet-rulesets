rule TTP_XOR_QUAD_CurrentVersionRun_fc5b {
  strings:
    $key_fc5b = { af 34 [2] 8b 3a [2] a0 16 [2] 8e 34 [2] 9a 2f [2] 95 35 [2] 8b 28 [2] 89 29 [2] 92 2f [2] 8e 28 [2] 92 07 }

  condition:
    any of them
}