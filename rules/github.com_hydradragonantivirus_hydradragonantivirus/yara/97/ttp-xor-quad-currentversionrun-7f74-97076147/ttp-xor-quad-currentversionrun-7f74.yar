rule TTP_XOR_QUAD_CurrentVersionRun_7f74 {
  strings:
    $key_7f74 = { 2c 1b [2] 08 15 [2] 23 39 [2] 0d 1b [2] 19 00 [2] 16 1a [2] 08 07 [2] 0a 06 [2] 11 00 [2] 0d 07 [2] 11 28 }

  condition:
    any of them
}