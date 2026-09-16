rule TTP_XOR_QUAD_CurrentVersionRun_0405 {
  strings:
    $key_0405 = { 57 6a [2] 73 64 [2] 58 48 [2] 76 6a [2] 62 71 [2] 6d 6b [2] 73 76 [2] 71 77 [2] 6a 71 [2] 76 76 [2] 6a 59 }

  condition:
    any of them
}