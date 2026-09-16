rule TTP_XOR_QUAD_CurrentVersionRun_74f9 {
  strings:
    $key_74f9 = { 27 96 [2] 03 98 [2] 28 b4 [2] 06 96 [2] 12 8d [2] 1d 97 [2] 03 8a [2] 01 8b [2] 1a 8d [2] 06 8a [2] 1a a5 }

  condition:
    any of them
}