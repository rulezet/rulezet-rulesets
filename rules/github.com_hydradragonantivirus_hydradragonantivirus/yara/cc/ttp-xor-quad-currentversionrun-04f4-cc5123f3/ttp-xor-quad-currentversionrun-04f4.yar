rule TTP_XOR_QUAD_CurrentVersionRun_04f4 {
  strings:
    $key_04f4 = { 57 9b [2] 73 95 [2] 58 b9 [2] 76 9b [2] 62 80 [2] 6d 9a [2] 73 87 [2] 71 86 [2] 6a 80 [2] 76 87 [2] 6a a8 }

  condition:
    any of them
}