rule TTP_XOR_QUAD_CurrentVersionRun_0464 {
  strings:
    $key_0464 = { 57 0b [2] 73 05 [2] 58 29 [2] 76 0b [2] 62 10 [2] 6d 0a [2] 73 17 [2] 71 16 [2] 6a 10 [2] 76 17 [2] 6a 38 }

  condition:
    any of them
}