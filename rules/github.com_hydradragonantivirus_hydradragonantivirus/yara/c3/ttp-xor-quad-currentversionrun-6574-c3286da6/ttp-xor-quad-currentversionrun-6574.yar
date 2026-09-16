rule TTP_XOR_QUAD_CurrentVersionRun_6574 {
  strings:
    $key_6574 = { 36 1b [2] 12 15 [2] 39 39 [2] 17 1b [2] 03 00 [2] 0c 1a [2] 12 07 [2] 10 06 [2] 0b 00 [2] 17 07 [2] 0b 28 }

  condition:
    any of them
}