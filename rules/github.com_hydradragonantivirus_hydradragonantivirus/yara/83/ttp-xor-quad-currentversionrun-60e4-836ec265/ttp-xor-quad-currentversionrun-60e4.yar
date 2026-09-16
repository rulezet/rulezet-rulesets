rule TTP_XOR_QUAD_CurrentVersionRun_60e4 {
  strings:
    $key_60e4 = { 33 8b [2] 17 85 [2] 3c a9 [2] 12 8b [2] 06 90 [2] 09 8a [2] 17 97 [2] 15 96 [2] 0e 90 [2] 12 97 [2] 0e b8 }

  condition:
    any of them
}