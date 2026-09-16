rule TTP_XOR_QUAD_CurrentVersionRun_71f5 {
  strings:
    $key_71f5 = { 22 9a [2] 06 94 [2] 2d b8 [2] 03 9a [2] 17 81 [2] 18 9b [2] 06 86 [2] 04 87 [2] 1f 81 [2] 03 86 [2] 1f a9 }

  condition:
    any of them
}