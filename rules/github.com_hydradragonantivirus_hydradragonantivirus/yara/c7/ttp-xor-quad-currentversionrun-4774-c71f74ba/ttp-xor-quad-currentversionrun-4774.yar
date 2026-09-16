rule TTP_XOR_QUAD_CurrentVersionRun_4774 {
  strings:
    $key_4774 = { 14 1b [2] 30 15 [2] 1b 39 [2] 35 1b [2] 21 00 [2] 2e 1a [2] 30 07 [2] 32 06 [2] 29 00 [2] 35 07 [2] 29 28 }

  condition:
    any of them
}