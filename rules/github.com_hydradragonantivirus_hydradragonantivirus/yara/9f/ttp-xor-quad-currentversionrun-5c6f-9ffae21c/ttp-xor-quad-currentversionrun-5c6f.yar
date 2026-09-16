rule TTP_XOR_QUAD_CurrentVersionRun_5c6f {
  strings:
    $key_5c6f = { 0f 00 [2] 2b 0e [2] 00 22 [2] 2e 00 [2] 3a 1b [2] 35 01 [2] 2b 1c [2] 29 1d [2] 32 1b [2] 2e 1c [2] 32 33 }

  condition:
    any of them
}