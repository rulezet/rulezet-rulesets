rule TTP_XOR_QUAD_CurrentVersionRun_7568 {
  strings:
    $key_7568 = { 26 07 [2] 02 09 [2] 29 25 [2] 07 07 [2] 13 1c [2] 1c 06 [2] 02 1b [2] 00 1a [2] 1b 1c [2] 07 1b [2] 1b 34 }

  condition:
    any of them
}