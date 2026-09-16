rule TTP_XOR_QUAD_CurrentVersionRun_7527 {
  strings:
    $key_7527 = { 26 48 [2] 02 46 [2] 29 6a [2] 07 48 [2] 13 53 [2] 1c 49 [2] 02 54 [2] 00 55 [2] 1b 53 [2] 07 54 [2] 1b 7b }

  condition:
    any of them
}