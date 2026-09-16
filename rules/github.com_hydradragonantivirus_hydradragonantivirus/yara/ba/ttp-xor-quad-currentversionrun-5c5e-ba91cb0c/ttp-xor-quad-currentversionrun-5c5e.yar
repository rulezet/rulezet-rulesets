rule TTP_XOR_QUAD_CurrentVersionRun_5c5e {
  strings:
    $key_5c5e = { 0f 31 [2] 2b 3f [2] 00 13 [2] 2e 31 [2] 3a 2a [2] 35 30 [2] 2b 2d [2] 29 2c [2] 32 2a [2] 2e 2d [2] 32 02 }

  condition:
    any of them
}