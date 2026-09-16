rule TTP_XOR_QUAD_CurrentVersionRun_5c04 {
  strings:
    $key_5c04 = { 0f 6b [2] 2b 65 [2] 00 49 [2] 2e 6b [2] 3a 70 [2] 35 6a [2] 2b 77 [2] 29 76 [2] 32 70 [2] 2e 77 [2] 32 58 }

  condition:
    any of them
}