rule TTP_XOR_QUAD_CurrentVersionRun_4766 {
  strings:
    $key_4766 = { 14 09 [2] 30 07 [2] 1b 2b [2] 35 09 [2] 21 12 [2] 2e 08 [2] 30 15 [2] 32 14 [2] 29 12 [2] 35 15 [2] 29 3a }

  condition:
    any of them
}