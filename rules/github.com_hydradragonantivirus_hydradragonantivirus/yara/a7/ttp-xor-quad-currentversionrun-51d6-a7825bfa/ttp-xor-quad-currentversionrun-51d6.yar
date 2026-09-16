rule TTP_XOR_QUAD_CurrentVersionRun_51d6 {
  strings:
    $key_51d6 = { 02 b9 [2] 26 b7 [2] 0d 9b [2] 23 b9 [2] 37 a2 [2] 38 b8 [2] 26 a5 [2] 24 a4 [2] 3f a2 [2] 23 a5 [2] 3f 8a }

  condition:
    any of them
}