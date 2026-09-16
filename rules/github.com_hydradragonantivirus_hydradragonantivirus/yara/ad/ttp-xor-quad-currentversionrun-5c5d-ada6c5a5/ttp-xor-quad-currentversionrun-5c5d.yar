rule TTP_XOR_QUAD_CurrentVersionRun_5c5d {
  strings:
    $key_5c5d = { 0f 32 [2] 2b 3c [2] 00 10 [2] 2e 32 [2] 3a 29 [2] 35 33 [2] 2b 2e [2] 29 2f [2] 32 29 [2] 2e 2e [2] 32 01 }

  condition:
    any of them
}