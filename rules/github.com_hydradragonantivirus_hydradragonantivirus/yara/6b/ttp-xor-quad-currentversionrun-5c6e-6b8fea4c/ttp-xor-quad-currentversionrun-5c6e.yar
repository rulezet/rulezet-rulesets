rule TTP_XOR_QUAD_CurrentVersionRun_5c6e {
  strings:
    $key_5c6e = { 0f 01 [2] 2b 0f [2] 00 23 [2] 2e 01 [2] 3a 1a [2] 35 00 [2] 2b 1d [2] 29 1c [2] 32 1a [2] 2e 1d [2] 32 32 }

  condition:
    any of them
}