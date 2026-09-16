rule TTP_XOR_QUAD_CurrentVersionRun_7236 {
  strings:
    $key_7236 = { 21 59 [2] 05 57 [2] 2e 7b [2] 00 59 [2] 14 42 [2] 1b 58 [2] 05 45 [2] 07 44 [2] 1c 42 [2] 00 45 [2] 1c 6a }

  condition:
    any of them
}