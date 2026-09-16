rule TTP_XOR_QUAD_CurrentVersionRun_01c6 {
  strings:
    $key_01c6 = { 52 a9 [2] 76 a7 [2] 5d 8b [2] 73 a9 [2] 67 b2 [2] 68 a8 [2] 76 b5 [2] 74 b4 [2] 6f b2 [2] 73 b5 [2] 6f 9a }

  condition:
    any of them
}