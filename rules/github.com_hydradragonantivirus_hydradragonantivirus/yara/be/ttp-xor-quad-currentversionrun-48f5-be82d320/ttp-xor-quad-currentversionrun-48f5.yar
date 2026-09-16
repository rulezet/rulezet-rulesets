rule TTP_XOR_QUAD_CurrentVersionRun_48f5 {
  strings:
    $key_48f5 = { 1b 9a [2] 3f 94 [2] 14 b8 [2] 3a 9a [2] 2e 81 [2] 21 9b [2] 3f 86 [2] 3d 87 [2] 26 81 [2] 3a 86 [2] 26 a9 }

  condition:
    any of them
}