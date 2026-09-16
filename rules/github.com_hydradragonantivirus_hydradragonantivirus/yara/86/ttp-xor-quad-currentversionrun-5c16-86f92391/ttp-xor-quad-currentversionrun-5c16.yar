rule TTP_XOR_QUAD_CurrentVersionRun_5c16 {
  strings:
    $key_5c16 = { 0f 79 [2] 2b 77 [2] 00 5b [2] 2e 79 [2] 3a 62 [2] 35 78 [2] 2b 65 [2] 29 64 [2] 32 62 [2] 2e 65 [2] 32 4a }

  condition:
    any of them
}