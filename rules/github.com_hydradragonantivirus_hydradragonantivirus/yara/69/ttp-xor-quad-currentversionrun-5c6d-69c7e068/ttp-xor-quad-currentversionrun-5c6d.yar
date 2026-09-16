rule TTP_XOR_QUAD_CurrentVersionRun_5c6d {
  strings:
    $key_5c6d = { 0f 02 [2] 2b 0c [2] 00 20 [2] 2e 02 [2] 3a 19 [2] 35 03 [2] 2b 1e [2] 29 1f [2] 32 19 [2] 2e 1e [2] 32 31 }

  condition:
    any of them
}