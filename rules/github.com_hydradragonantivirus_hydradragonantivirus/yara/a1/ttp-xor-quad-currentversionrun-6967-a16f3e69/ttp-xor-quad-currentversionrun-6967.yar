rule TTP_XOR_QUAD_CurrentVersionRun_6967 {
  strings:
    $key_6967 = { 3a 08 [2] 1e 06 [2] 35 2a [2] 1b 08 [2] 0f 13 [2] 00 09 [2] 1e 14 [2] 1c 15 [2] 07 13 [2] 1b 14 [2] 07 3b }

  condition:
    any of them
}