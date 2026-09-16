rule TTP_XOR_QUAD_CurrentVersionRun_7174 {
  strings:
    $key_7174 = { 22 1b [2] 06 15 [2] 2d 39 [2] 03 1b [2] 17 00 [2] 18 1a [2] 06 07 [2] 04 06 [2] 1f 00 [2] 03 07 [2] 1f 28 }

  condition:
    any of them
}