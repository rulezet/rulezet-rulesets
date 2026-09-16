rule TTP_XOR_QUAD_CurrentVersionRun_7559 {
  strings:
    $key_7559 = { 26 36 [2] 02 38 [2] 29 14 [2] 07 36 [2] 13 2d [2] 1c 37 [2] 02 2a [2] 00 2b [2] 1b 2d [2] 07 2a [2] 1b 05 }

  condition:
    any of them
}