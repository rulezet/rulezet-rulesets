rule TTP_XOR_QUAD_CurrentVersionRun_5c5a {
  strings:
    $key_5c5a = { 0f 35 [2] 2b 3b [2] 00 17 [2] 2e 35 [2] 3a 2e [2] 35 34 [2] 2b 29 [2] 29 28 [2] 32 2e [2] 2e 29 [2] 32 06 }

  condition:
    any of them
}