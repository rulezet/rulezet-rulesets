rule TTP_XOR_QUAD_CurrentVersionRun_04d6 {
  strings:
    $key_04d6 = { 57 b9 [2] 73 b7 [2] 58 9b [2] 76 b9 [2] 62 a2 [2] 6d b8 [2] 73 a5 [2] 71 a4 [2] 6a a2 [2] 76 a5 [2] 6a 8a }

  condition:
    any of them
}