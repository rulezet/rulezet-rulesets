rule TTP_XOR_QUAD_CurrentVersionRun_63c7 {
  strings:
    $key_63c7 = { 30 a8 [2] 14 a6 [2] 3f 8a [2] 11 a8 [2] 05 b3 [2] 0a a9 [2] 14 b4 [2] 16 b5 [2] 0d b3 [2] 11 b4 [2] 0d 9b }

  condition:
    any of them
}