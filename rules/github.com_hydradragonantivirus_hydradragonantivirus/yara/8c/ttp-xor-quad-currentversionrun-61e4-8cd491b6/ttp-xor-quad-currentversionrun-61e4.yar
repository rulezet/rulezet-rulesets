rule TTP_XOR_QUAD_CurrentVersionRun_61e4 {
  strings:
    $key_61e4 = { 32 8b [2] 16 85 [2] 3d a9 [2] 13 8b [2] 07 90 [2] 08 8a [2] 16 97 [2] 14 96 [2] 0f 90 [2] 13 97 [2] 0f b8 }

  condition:
    any of them
}