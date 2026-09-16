rule TTP_XOR_QUAD_CurrentVersionRun_7525 {
  strings:
    $key_7525 = { 26 4a [2] 02 44 [2] 29 68 [2] 07 4a [2] 13 51 [2] 1c 4b [2] 02 56 [2] 00 57 [2] 1b 51 [2] 07 56 [2] 1b 79 }

  condition:
    any of them
}