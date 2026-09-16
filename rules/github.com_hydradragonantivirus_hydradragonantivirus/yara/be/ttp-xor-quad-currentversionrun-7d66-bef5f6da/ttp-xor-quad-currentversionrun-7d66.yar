rule TTP_XOR_QUAD_CurrentVersionRun_7d66 {
  strings:
    $key_7d66 = { 2e 09 [2] 0a 07 [2] 21 2b [2] 0f 09 [2] 1b 12 [2] 14 08 [2] 0a 15 [2] 08 14 [2] 13 12 [2] 0f 15 [2] 13 3a }

  condition:
    any of them
}