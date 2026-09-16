rule TTP_XOR_QUAD_CurrentVersionRun_71c7 {
  strings:
    $key_71c7 = { 22 a8 [2] 06 a6 [2] 2d 8a [2] 03 a8 [2] 17 b3 [2] 18 a9 [2] 06 b4 [2] 04 b5 [2] 1f b3 [2] 03 b4 [2] 1f 9b }

  condition:
    any of them
}