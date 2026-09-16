rule TTP_XOR_QUAD_CurrentVersionRun_64f4 {
  strings:
    $key_64f4 = { 37 9b [2] 13 95 [2] 38 b9 [2] 16 9b [2] 02 80 [2] 0d 9a [2] 13 87 [2] 11 86 [2] 0a 80 [2] 16 87 [2] 0a a8 }

  condition:
    any of them
}