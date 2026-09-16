rule TTP_XOR_QUAD_CurrentVersionRun_5c47 {
  strings:
    $key_5c47 = { 0f 28 [2] 2b 26 [2] 00 0a [2] 2e 28 [2] 3a 33 [2] 35 29 [2] 2b 34 [2] 29 35 [2] 32 33 [2] 2e 34 [2] 32 1b }

  condition:
    any of them
}