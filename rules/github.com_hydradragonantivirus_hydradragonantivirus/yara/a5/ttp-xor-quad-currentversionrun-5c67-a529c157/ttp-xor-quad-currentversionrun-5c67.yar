rule TTP_XOR_QUAD_CurrentVersionRun_5c67 {
  strings:
    $key_5c67 = { 0f 08 [2] 2b 06 [2] 00 2a [2] 2e 08 [2] 3a 13 [2] 35 09 [2] 2b 14 [2] 29 15 [2] 32 13 [2] 2e 14 [2] 32 3b }

  condition:
    any of them
}