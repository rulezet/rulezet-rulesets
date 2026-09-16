rule TTP_XOR_QUAD_CurrentVersionRun_7c75 {
  strings:
    $key_7c75 = { 2f 1a [2] 0b 14 [2] 20 38 [2] 0e 1a [2] 1a 01 [2] 15 1b [2] 0b 06 [2] 09 07 [2] 12 01 [2] 0e 06 [2] 12 29 }

  condition:
    any of them
}