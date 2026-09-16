rule TTP_XOR_QUAD_CurrentVersionRun_5c7c {
  strings:
    $key_5c7c = { 0f 13 [2] 2b 1d [2] 00 31 [2] 2e 13 [2] 3a 08 [2] 35 12 [2] 2b 0f [2] 29 0e [2] 32 08 [2] 2e 0f [2] 32 20 }

  condition:
    any of them
}