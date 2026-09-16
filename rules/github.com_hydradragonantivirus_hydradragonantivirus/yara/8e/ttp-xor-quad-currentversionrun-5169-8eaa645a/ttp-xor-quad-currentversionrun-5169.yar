rule TTP_XOR_QUAD_CurrentVersionRun_5169 {
  strings:
    $key_5169 = { 02 06 [2] 26 08 [2] 0d 24 [2] 23 06 [2] 37 1d [2] 38 07 [2] 26 1a [2] 24 1b [2] 3f 1d [2] 23 1a [2] 3f 35 }

  condition:
    any of them
}