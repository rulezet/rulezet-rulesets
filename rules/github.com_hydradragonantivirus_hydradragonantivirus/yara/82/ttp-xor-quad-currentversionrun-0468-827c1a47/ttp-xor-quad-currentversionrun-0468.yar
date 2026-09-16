rule TTP_XOR_QUAD_CurrentVersionRun_0468 {
  strings:
    $key_0468 = { 57 07 [2] 73 09 [2] 58 25 [2] 76 07 [2] 62 1c [2] 6d 06 [2] 73 1b [2] 71 1a [2] 6a 1c [2] 76 1b [2] 6a 34 }

  condition:
    any of them
}