rule TTP_XOR_QUAD_CurrentVersionRun_7267 {
  strings:
    $key_7267 = { 21 08 [2] 05 06 [2] 2e 2a [2] 00 08 [2] 14 13 [2] 1b 09 [2] 05 14 [2] 07 15 [2] 1c 13 [2] 00 14 [2] 1c 3b }

  condition:
    any of them
}