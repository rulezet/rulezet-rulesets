rule TTP_XOR_QUAD_CurrentVersionRun_754b {
  strings:
    $key_754b = { 26 24 [2] 02 2a [2] 29 06 [2] 07 24 [2] 13 3f [2] 1c 25 [2] 02 38 [2] 00 39 [2] 1b 3f [2] 07 38 [2] 1b 17 }

  condition:
    any of them
}