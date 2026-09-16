rule TTP_XOR_QUAD_CurrentVersionRun_51d7 {
  strings:
    $key_51d7 = { 02 b8 [2] 26 b6 [2] 0d 9a [2] 23 b8 [2] 37 a3 [2] 38 b9 [2] 26 a4 [2] 24 a5 [2] 3f a3 [2] 23 a4 [2] 3f 8b }

  condition:
    any of them
}