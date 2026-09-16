rule TTP_XOR_QUAD_CurrentVersionRun_11c7 {
  strings:
    $key_11c7 = { 42 a8 [2] 66 a6 [2] 4d 8a [2] 63 a8 [2] 77 b3 [2] 78 a9 [2] 66 b4 [2] 64 b5 [2] 7f b3 [2] 63 b4 [2] 7f 9b }

  condition:
    any of them
}