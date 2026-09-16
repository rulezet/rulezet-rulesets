rule TTP_XOR_QUAD_CurrentVersionRun_0478 {
  strings:
    $key_0478 = { 57 17 [2] 73 19 [2] 58 35 [2] 76 17 [2] 62 0c [2] 6d 16 [2] 73 0b [2] 71 0a [2] 6a 0c [2] 76 0b [2] 6a 24 }

  condition:
    any of them
}