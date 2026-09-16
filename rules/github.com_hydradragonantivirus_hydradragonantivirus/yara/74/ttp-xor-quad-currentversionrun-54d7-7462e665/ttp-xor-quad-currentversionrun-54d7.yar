rule TTP_XOR_QUAD_CurrentVersionRun_54d7 {
  strings:
    $key_54d7 = { 07 b8 [2] 23 b6 [2] 08 9a [2] 26 b8 [2] 32 a3 [2] 3d b9 [2] 23 a4 [2] 21 a5 [2] 3a a3 [2] 26 a4 [2] 3a 8b }

  condition:
    any of them
}