rule TTP_XOR_QUAD_CurrentVersionRun_5c24 {
  strings:
    $key_5c24 = { 0f 4b [2] 2b 45 [2] 00 69 [2] 2e 4b [2] 3a 50 [2] 35 4a [2] 2b 57 [2] 29 56 [2] 32 50 [2] 2e 57 [2] 32 78 }

  condition:
    any of them
}