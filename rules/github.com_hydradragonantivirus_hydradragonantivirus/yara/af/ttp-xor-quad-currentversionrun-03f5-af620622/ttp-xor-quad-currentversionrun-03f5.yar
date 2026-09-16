rule TTP_XOR_QUAD_CurrentVersionRun_03f5 {
  strings:
    $key_03f5 = { 50 9a [2] 74 94 [2] 5f b8 [2] 71 9a [2] 65 81 [2] 6a 9b [2] 74 86 [2] 76 87 [2] 6d 81 [2] 71 86 [2] 6d a9 }

  condition:
    any of them
}