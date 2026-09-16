rule TTP_XOR_QUAD_CurrentVersionRun_7574 {
  strings:
    $key_7574 = { 26 1b [2] 02 15 [2] 29 39 [2] 07 1b [2] 13 00 [2] 1c 1a [2] 02 07 [2] 00 06 [2] 1b 00 [2] 07 07 [2] 1b 28 }

  condition:
    any of them
}