rule TTP_XOR_QUAD_CurrentVersionRun_71d6 {
  strings:
    $key_71d6 = { 22 b9 [2] 06 b7 [2] 2d 9b [2] 03 b9 [2] 17 a2 [2] 18 b8 [2] 06 a5 [2] 04 a4 [2] 1f a2 [2] 03 a5 [2] 1f 8a }

  condition:
    any of them
}