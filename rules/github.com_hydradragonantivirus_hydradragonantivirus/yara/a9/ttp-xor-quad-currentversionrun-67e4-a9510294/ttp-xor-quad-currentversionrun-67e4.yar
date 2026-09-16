rule TTP_XOR_QUAD_CurrentVersionRun_67e4 {
  strings:
    $key_67e4 = { 34 8b [2] 10 85 [2] 3b a9 [2] 15 8b [2] 01 90 [2] 0e 8a [2] 10 97 [2] 12 96 [2] 09 90 [2] 15 97 [2] 09 b8 }

  condition:
    any of them
}