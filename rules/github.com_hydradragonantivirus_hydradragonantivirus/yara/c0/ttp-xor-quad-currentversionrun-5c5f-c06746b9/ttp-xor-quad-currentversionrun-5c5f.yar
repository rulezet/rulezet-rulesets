rule TTP_XOR_QUAD_CurrentVersionRun_5c5f {
  strings:
    $key_5c5f = { 0f 30 [2] 2b 3e [2] 00 12 [2] 2e 30 [2] 3a 2b [2] 35 31 [2] 2b 2c [2] 29 2d [2] 32 2b [2] 2e 2c [2] 32 03 }

  condition:
    any of them
}