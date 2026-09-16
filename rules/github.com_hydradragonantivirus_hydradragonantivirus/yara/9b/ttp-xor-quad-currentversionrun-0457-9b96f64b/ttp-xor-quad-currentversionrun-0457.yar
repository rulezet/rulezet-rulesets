rule TTP_XOR_QUAD_CurrentVersionRun_0457 {
  strings:
    $key_0457 = { 57 38 [2] 73 36 [2] 58 1a [2] 76 38 [2] 62 23 [2] 6d 39 [2] 73 24 [2] 71 25 [2] 6a 23 [2] 76 24 [2] 6a 0b }

  condition:
    any of them
}