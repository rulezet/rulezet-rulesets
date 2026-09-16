rule TTP_XOR_QUAD_CurrentVersionRun_5c7f {
  strings:
    $key_5c7f = { 0f 10 [2] 2b 1e [2] 00 32 [2] 2e 10 [2] 3a 0b [2] 35 11 [2] 2b 0c [2] 29 0d [2] 32 0b [2] 2e 0c [2] 32 23 }

  condition:
    any of them
}