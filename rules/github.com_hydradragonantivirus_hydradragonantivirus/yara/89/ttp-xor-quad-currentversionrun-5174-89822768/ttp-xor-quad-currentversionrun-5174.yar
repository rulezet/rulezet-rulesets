rule TTP_XOR_QUAD_CurrentVersionRun_5174 {
  strings:
    $key_5174 = { 02 1b [2] 26 15 [2] 0d 39 [2] 23 1b [2] 37 00 [2] 38 1a [2] 26 07 [2] 24 06 [2] 3f 00 [2] 23 07 [2] 3f 28 }

  condition:
    any of them
}