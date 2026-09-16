rule TTP_XOR_QUAD_CurrentVersionRun_5c54 {
  strings:
    $key_5c54 = { 0f 3b [2] 2b 35 [2] 00 19 [2] 2e 3b [2] 3a 20 [2] 35 3a [2] 2b 27 [2] 29 26 [2] 32 20 [2] 2e 27 [2] 32 08 }

  condition:
    any of them
}