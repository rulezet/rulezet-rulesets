rule TTP_XOR_QUAD_CurrentVersionRun_4757 {
  strings:
    $key_4757 = { 14 38 [2] 30 36 [2] 1b 1a [2] 35 38 [2] 21 23 [2] 2e 39 [2] 30 24 [2] 32 25 [2] 29 23 [2] 35 24 [2] 29 0b }

  condition:
    any of them
}