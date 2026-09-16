rule TTP_XOR_QUAD_CurrentVersionRun_7569 {
  strings:
    $key_7569 = { 26 06 [2] 02 08 [2] 29 24 [2] 07 06 [2] 13 1d [2] 1c 07 [2] 02 1a [2] 00 1b [2] 1b 1d [2] 07 1a [2] 1b 35 }

  condition:
    any of them
}