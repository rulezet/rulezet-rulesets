rule TTP_XOR_QUAD_CurrentVersionRun_51c7 {
  strings:
    $key_51c7 = { 02 a8 [2] 26 a6 [2] 0d 8a [2] 23 a8 [2] 37 b3 [2] 38 a9 [2] 26 b4 [2] 24 b5 [2] 3f b3 [2] 23 b4 [2] 3f 9b }

  condition:
    any of them
}