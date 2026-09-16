rule TTP_XOR_QUAD_CurrentVersionRun_01e4 {
  strings:
    $key_01e4 = { 52 8b [2] 76 85 [2] 5d a9 [2] 73 8b [2] 67 90 [2] 68 8a [2] 76 97 [2] 74 96 [2] 6f 90 [2] 73 97 [2] 6f b8 }

  condition:
    any of them
}