rule TTP_XOR_QUAD_CurrentVersionRun_71e4 {
  strings:
    $key_71e4 = { 22 8b [2] 06 85 [2] 2d a9 [2] 03 8b [2] 17 90 [2] 18 8a [2] 06 97 [2] 04 96 [2] 1f 90 [2] 03 97 [2] 1f b8 }

  condition:
    any of them
}