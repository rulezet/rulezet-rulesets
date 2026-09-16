rule TTP_XOR_QUAD_CurrentVersionRun_0447 {
  strings:
    $key_0447 = { 57 28 [2] 73 26 [2] 58 0a [2] 76 28 [2] 62 33 [2] 6d 29 [2] 73 34 [2] 71 35 [2] 6a 33 [2] 76 34 [2] 6a 1b }

  condition:
    any of them
}