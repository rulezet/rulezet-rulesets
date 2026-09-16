rule TTP_XOR_QUAD_CurrentVersionRun_7c74 {
  strings:
    $key_7c74 = { 2f 1b [2] 0b 15 [2] 20 39 [2] 0e 1b [2] 1a 00 [2] 15 1a [2] 0b 07 [2] 09 06 [2] 12 00 [2] 0e 07 [2] 12 28 }

  condition:
    any of them
}