rule TTP_XOR_QUAD_CurrentVersionRun_5c37 {
  strings:
    $key_5c37 = { 0f 58 [2] 2b 56 [2] 00 7a [2] 2e 58 [2] 3a 43 [2] 35 59 [2] 2b 44 [2] 29 45 [2] 32 43 [2] 2e 44 [2] 32 6b }

  condition:
    any of them
}