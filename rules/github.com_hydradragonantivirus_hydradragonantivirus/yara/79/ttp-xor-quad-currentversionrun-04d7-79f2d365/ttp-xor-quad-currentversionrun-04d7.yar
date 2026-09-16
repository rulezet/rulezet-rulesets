rule TTP_XOR_QUAD_CurrentVersionRun_04d7 {
  strings:
    $key_04d7 = { 57 b8 [2] 73 b6 [2] 58 9a [2] 76 b8 [2] 62 a3 [2] 6d b9 [2] 73 a4 [2] 71 a5 [2] 6a a3 [2] 76 a4 [2] 6a 8b }

  condition:
    any of them
}