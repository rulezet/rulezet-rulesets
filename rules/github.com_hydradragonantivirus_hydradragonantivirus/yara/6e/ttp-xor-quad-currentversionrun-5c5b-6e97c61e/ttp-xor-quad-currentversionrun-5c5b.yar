rule TTP_XOR_QUAD_CurrentVersionRun_5c5b {
  strings:
    $key_5c5b = { 0f 34 [2] 2b 3a [2] 00 16 [2] 2e 34 [2] 3a 2f [2] 35 35 [2] 2b 28 [2] 29 29 [2] 32 2f [2] 2e 28 [2] 32 07 }

  condition:
    any of them
}