rule TTP_XOR_QUAD_CurrentVersionRun_5c39 {
  strings:
    $key_5c39 = { 0f 56 [2] 2b 58 [2] 00 74 [2] 2e 56 [2] 3a 4d [2] 35 57 [2] 2b 4a [2] 29 4b [2] 32 4d [2] 2e 4a [2] 32 65 }

  condition:
    any of them
}