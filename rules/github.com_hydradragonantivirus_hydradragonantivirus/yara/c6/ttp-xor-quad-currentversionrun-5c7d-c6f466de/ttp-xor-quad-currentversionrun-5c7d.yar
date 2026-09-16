rule TTP_XOR_QUAD_CurrentVersionRun_5c7d {
  strings:
    $key_5c7d = { 0f 12 [2] 2b 1c [2] 00 30 [2] 2e 12 [2] 3a 09 [2] 35 13 [2] 2b 0e [2] 29 0f [2] 32 09 [2] 2e 0e [2] 32 21 }

  condition:
    any of them
}