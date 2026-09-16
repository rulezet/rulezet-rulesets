rule TTP_XOR_QUAD_CurrentVersionRun_5c1d {
  strings:
    $key_5c1d = { 0f 72 [2] 2b 7c [2] 00 50 [2] 2e 72 [2] 3a 69 [2] 35 73 [2] 2b 6e [2] 29 6f [2] 32 69 [2] 2e 6e [2] 32 41 }

  condition:
    any of them
}