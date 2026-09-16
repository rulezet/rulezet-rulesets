rule TTP_XOR_QUAD_CurrentVersionRun_0455 {
  strings:
    $key_0455 = { 57 3a [2] 73 34 [2] 58 18 [2] 76 3a [2] 62 21 [2] 6d 3b [2] 73 26 [2] 71 27 [2] 6a 21 [2] 76 26 [2] 6a 09 }

  condition:
    any of them
}