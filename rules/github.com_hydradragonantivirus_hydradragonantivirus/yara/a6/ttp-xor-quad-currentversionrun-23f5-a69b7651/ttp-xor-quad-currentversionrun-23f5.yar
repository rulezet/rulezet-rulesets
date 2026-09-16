rule TTP_XOR_QUAD_CurrentVersionRun_23f5 {
  strings:
    $key_23f5 = { 70 9a [2] 54 94 [2] 7f b8 [2] 51 9a [2] 45 81 [2] 4a 9b [2] 54 86 [2] 56 87 [2] 4d 81 [2] 51 86 [2] 4d a9 }

  condition:
    any of them
}