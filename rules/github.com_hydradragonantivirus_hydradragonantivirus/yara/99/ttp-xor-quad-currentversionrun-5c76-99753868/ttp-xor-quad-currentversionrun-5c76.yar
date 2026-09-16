rule TTP_XOR_QUAD_CurrentVersionRun_5c76 {
  strings:
    $key_5c76 = { 0f 19 [2] 2b 17 [2] 00 3b [2] 2e 19 [2] 3a 02 [2] 35 18 [2] 2b 05 [2] 29 04 [2] 32 02 [2] 2e 05 [2] 32 2a }

  condition:
    any of them
}