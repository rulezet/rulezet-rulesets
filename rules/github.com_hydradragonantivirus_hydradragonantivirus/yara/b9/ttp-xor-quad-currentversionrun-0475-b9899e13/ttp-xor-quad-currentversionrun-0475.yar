rule TTP_XOR_QUAD_CurrentVersionRun_0475 {
  strings:
    $key_0475 = { 57 1a [2] 73 14 [2] 58 38 [2] 76 1a [2] 62 01 [2] 6d 1b [2] 73 06 [2] 71 07 [2] 6a 01 [2] 76 06 [2] 6a 29 }

  condition:
    any of them
}