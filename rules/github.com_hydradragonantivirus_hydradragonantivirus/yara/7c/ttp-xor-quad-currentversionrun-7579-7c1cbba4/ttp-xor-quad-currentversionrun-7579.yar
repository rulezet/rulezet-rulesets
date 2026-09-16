rule TTP_XOR_QUAD_CurrentVersionRun_7579 {
  strings:
    $key_7579 = { 26 16 [2] 02 18 [2] 29 34 [2] 07 16 [2] 13 0d [2] 1c 17 [2] 02 0a [2] 00 0b [2] 1b 0d [2] 07 0a [2] 1b 25 }

  condition:
    any of them
}