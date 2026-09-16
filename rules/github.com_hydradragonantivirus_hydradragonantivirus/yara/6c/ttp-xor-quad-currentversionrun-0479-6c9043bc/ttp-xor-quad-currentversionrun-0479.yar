rule TTP_XOR_QUAD_CurrentVersionRun_0479 {
  strings:
    $key_0479 = { 57 16 [2] 73 18 [2] 58 34 [2] 76 16 [2] 62 0d [2] 6d 17 [2] 73 0a [2] 71 0b [2] 6a 0d [2] 76 0a [2] 6a 25 }

  condition:
    any of them
}