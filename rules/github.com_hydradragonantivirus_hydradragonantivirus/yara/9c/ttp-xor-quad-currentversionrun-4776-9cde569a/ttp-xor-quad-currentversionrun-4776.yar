rule TTP_XOR_QUAD_CurrentVersionRun_4776 {
  strings:
    $key_4776 = { 14 19 [2] 30 17 [2] 1b 3b [2] 35 19 [2] 21 02 [2] 2e 18 [2] 30 05 [2] 32 04 [2] 29 02 [2] 35 05 [2] 29 2a }

  condition:
    any of them
}