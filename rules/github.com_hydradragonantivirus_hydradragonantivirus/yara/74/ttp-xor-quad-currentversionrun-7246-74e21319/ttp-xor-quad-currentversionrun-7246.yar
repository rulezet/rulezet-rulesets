rule TTP_XOR_QUAD_CurrentVersionRun_7246 {
  strings:
    $key_7246 = { 21 29 [2] 05 27 [2] 2e 0b [2] 00 29 [2] 14 32 [2] 1b 28 [2] 05 35 [2] 07 34 [2] 1c 32 [2] 00 35 [2] 1c 1a }

  condition:
    any of them
}