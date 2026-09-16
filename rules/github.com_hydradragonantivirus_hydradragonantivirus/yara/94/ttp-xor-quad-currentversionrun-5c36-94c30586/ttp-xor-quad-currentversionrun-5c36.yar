rule TTP_XOR_QUAD_CurrentVersionRun_5c36 {
  strings:
    $key_5c36 = { 0f 59 [2] 2b 57 [2] 00 7b [2] 2e 59 [2] 3a 42 [2] 35 58 [2] 2b 45 [2] 29 44 [2] 32 42 [2] 2e 45 [2] 32 6a }

  condition:
    any of them
}