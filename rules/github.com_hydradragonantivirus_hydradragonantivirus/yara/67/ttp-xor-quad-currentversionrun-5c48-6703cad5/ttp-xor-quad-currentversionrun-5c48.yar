rule TTP_XOR_QUAD_CurrentVersionRun_5c48 {
  strings:
    $key_5c48 = { 0f 27 [2] 2b 29 [2] 00 05 [2] 2e 27 [2] 3a 3c [2] 35 26 [2] 2b 3b [2] 29 3a [2] 32 3c [2] 2e 3b [2] 32 14 }

  condition:
    any of them
}