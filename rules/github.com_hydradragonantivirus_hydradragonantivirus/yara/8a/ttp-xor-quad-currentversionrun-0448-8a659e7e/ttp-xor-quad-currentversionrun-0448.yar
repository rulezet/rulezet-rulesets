rule TTP_XOR_QUAD_CurrentVersionRun_0448 {
  strings:
    $key_0448 = { 57 27 [2] 73 29 [2] 58 05 [2] 76 27 [2] 62 3c [2] 6d 26 [2] 73 3b [2] 71 3a [2] 6a 3c [2] 76 3b [2] 6a 14 }

  condition:
    any of them
}