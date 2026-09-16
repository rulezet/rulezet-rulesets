rule TTP_XOR_QUAD_CurrentVersionRun_0674 {
  strings:
    $key_0674 = { 55 1b [2] 71 15 [2] 5a 39 [2] 74 1b [2] 60 00 [2] 6f 1a [2] 71 07 [2] 73 06 [2] 68 00 [2] 74 07 [2] 68 28 }

  condition:
    any of them
}