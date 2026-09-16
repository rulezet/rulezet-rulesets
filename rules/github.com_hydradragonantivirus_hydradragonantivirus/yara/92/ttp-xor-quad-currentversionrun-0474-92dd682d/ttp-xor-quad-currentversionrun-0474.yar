rule TTP_XOR_QUAD_CurrentVersionRun_0474 {
  strings:
    $key_0474 = { 57 1b [2] 73 15 [2] 58 39 [2] 76 1b [2] 62 00 [2] 6d 1a [2] 73 07 [2] 71 06 [2] 6a 00 [2] 76 07 [2] 6a 28 }

  condition:
    any of them
}