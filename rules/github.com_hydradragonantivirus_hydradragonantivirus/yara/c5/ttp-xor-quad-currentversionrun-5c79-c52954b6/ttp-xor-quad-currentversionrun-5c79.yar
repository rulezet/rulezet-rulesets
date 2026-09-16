rule TTP_XOR_QUAD_CurrentVersionRun_5c79 {
  strings:
    $key_5c79 = { 0f 16 [2] 2b 18 [2] 00 34 [2] 2e 16 [2] 3a 0d [2] 35 17 [2] 2b 0a [2] 29 0b [2] 32 0d [2] 2e 0a [2] 32 25 }

  condition:
    any of them
}