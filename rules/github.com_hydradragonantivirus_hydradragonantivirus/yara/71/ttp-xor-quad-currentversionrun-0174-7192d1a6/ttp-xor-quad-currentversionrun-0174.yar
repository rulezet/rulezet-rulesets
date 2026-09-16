rule TTP_XOR_QUAD_CurrentVersionRun_0174 {
  strings:
    $key_0174 = { 52 1b [2] 76 15 [2] 5d 39 [2] 73 1b [2] 67 00 [2] 68 1a [2] 76 07 [2] 74 06 [2] 6f 00 [2] 73 07 [2] 6f 28 }

  condition:
    any of them
}