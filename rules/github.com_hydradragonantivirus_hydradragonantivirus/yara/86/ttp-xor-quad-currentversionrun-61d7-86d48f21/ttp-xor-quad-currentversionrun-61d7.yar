rule TTP_XOR_QUAD_CurrentVersionRun_61d7 {
  strings:
    $key_61d7 = { 32 b8 [2] 16 b6 [2] 3d 9a [2] 13 b8 [2] 07 a3 [2] 08 b9 [2] 16 a4 [2] 14 a5 [2] 0f a3 [2] 13 a4 [2] 0f 8b }

  condition:
    any of them
}