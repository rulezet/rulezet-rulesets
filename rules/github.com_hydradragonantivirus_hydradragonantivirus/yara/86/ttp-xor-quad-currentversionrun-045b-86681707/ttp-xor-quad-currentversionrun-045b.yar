rule TTP_XOR_QUAD_CurrentVersionRun_045b {
  strings:
    $key_045b = { 57 34 [2] 73 3a [2] 58 16 [2] 76 34 [2] 62 2f [2] 6d 35 [2] 73 28 [2] 71 29 [2] 6a 2f [2] 76 28 [2] 6a 07 }

  condition:
    any of them
}