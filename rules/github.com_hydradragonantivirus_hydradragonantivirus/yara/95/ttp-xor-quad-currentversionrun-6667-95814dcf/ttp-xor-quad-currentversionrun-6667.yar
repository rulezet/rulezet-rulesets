rule TTP_XOR_QUAD_CurrentVersionRun_6667 {
  strings:
    $key_6667 = { 35 08 [2] 11 06 [2] 3a 2a [2] 14 08 [2] 00 13 [2] 0f 09 [2] 11 14 [2] 13 15 [2] 08 13 [2] 14 14 [2] 08 3b }

  condition:
    any of them
}