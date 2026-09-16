rule TTP_XOR_QUAD_CurrentVersionRun_74f8 {
  strings:
    $key_74f8 = { 27 97 [2] 03 99 [2] 28 b5 [2] 06 97 [2] 12 8c [2] 1d 96 [2] 03 8b [2] 01 8a [2] 1a 8c [2] 06 8b [2] 1a a4 }

  condition:
    any of them
}