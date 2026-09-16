rule TTP_XOR_QUAD_CurrentVersionRun_5474 {
  strings:
    $key_5474 = { 07 1b [2] 23 15 [2] 08 39 [2] 26 1b [2] 32 00 [2] 3d 1a [2] 23 07 [2] 21 06 [2] 3a 00 [2] 26 07 [2] 3a 28 }

  condition:
    any of them
}