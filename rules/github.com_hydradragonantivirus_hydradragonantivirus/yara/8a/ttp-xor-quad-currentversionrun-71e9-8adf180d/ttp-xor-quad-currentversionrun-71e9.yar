rule TTP_XOR_QUAD_CurrentVersionRun_71e9 {
  strings:
    $key_71e9 = { 22 86 [2] 06 88 [2] 2d a4 [2] 03 86 [2] 17 9d [2] 18 87 [2] 06 9a [2] 04 9b [2] 1f 9d [2] 03 9a [2] 1f b5 }

  condition:
    any of them
}