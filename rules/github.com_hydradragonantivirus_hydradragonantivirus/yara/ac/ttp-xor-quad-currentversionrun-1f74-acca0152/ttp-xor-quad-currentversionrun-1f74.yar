rule TTP_XOR_QUAD_CurrentVersionRun_1f74 {
  strings:
    $key_1f74 = { 4c 1b [2] 68 15 [2] 43 39 [2] 6d 1b [2] 79 00 [2] 76 1a [2] 68 07 [2] 6a 06 [2] 71 00 [2] 6d 07 [2] 71 28 }

  condition:
    any of them
}