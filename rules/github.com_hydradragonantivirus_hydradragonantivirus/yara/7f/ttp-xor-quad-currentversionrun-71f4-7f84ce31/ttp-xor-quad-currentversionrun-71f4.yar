rule TTP_XOR_QUAD_CurrentVersionRun_71f4 {
  strings:
    $key_71f4 = { 22 9b [2] 06 95 [2] 2d b9 [2] 03 9b [2] 17 80 [2] 18 9a [2] 06 87 [2] 04 86 [2] 1f 80 [2] 03 87 [2] 1f a8 }

  condition:
    any of them
}