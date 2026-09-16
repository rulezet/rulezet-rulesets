rule TTP_XOR_QUAD_CurrentVersionRun_68e4 {
  strings:
    $key_68e4 = { 3b 8b [2] 1f 85 [2] 34 a9 [2] 1a 8b [2] 0e 90 [2] 01 8a [2] 1f 97 [2] 1d 96 [2] 06 90 [2] 1a 97 [2] 06 b8 }

  condition:
    any of them
}