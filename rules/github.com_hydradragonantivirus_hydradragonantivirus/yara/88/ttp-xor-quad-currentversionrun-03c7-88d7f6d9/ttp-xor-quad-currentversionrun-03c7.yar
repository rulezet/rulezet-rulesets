rule TTP_XOR_QUAD_CurrentVersionRun_03c7 {
  strings:
    $key_03c7 = { 50 a8 [2] 74 a6 [2] 5f 8a [2] 71 a8 [2] 65 b3 [2] 6a a9 [2] 74 b4 [2] 76 b5 [2] 6d b3 [2] 71 b4 [2] 6d 9b }

  condition:
    any of them
}