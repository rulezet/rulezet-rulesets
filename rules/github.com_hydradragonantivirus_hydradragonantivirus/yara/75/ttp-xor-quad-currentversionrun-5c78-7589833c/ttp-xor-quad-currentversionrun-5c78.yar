rule TTP_XOR_QUAD_CurrentVersionRun_5c78 {
  strings:
    $key_5c78 = { 0f 17 [2] 2b 19 [2] 00 35 [2] 2e 17 [2] 3a 0c [2] 35 16 [2] 2b 0b [2] 29 0a [2] 32 0c [2] 2e 0b [2] 32 24 }

  condition:
    any of them
}