rule TTP_XOR_QUAD_CurrentVersionRun_6475 {
  strings:
    $key_6475 = { 37 1a [2] 13 14 [2] 38 38 [2] 16 1a [2] 02 01 [2] 0d 1b [2] 13 06 [2] 11 07 [2] 0a 01 [2] 16 06 [2] 0a 29 }

  condition:
    any of them
}