rule TTP_XOR_QUAD_CurrentVersionRun_54c7 {
  strings:
    $key_54c7 = { 07 a8 [2] 23 a6 [2] 08 8a [2] 26 a8 [2] 32 b3 [2] 3d a9 [2] 23 b4 [2] 21 b5 [2] 3a b3 [2] 26 b4 [2] 3a 9b }

  condition:
    any of them
}