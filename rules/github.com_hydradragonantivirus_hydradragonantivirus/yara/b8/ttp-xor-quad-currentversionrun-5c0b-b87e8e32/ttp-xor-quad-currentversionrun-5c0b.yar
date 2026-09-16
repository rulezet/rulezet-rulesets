rule TTP_XOR_QUAD_CurrentVersionRun_5c0b {
  strings:
    $key_5c0b = { 0f 64 [2] 2b 6a [2] 00 46 [2] 2e 64 [2] 3a 7f [2] 35 65 [2] 2b 78 [2] 29 79 [2] 32 7f [2] 2e 78 [2] 32 57 }

  condition:
    any of them
}