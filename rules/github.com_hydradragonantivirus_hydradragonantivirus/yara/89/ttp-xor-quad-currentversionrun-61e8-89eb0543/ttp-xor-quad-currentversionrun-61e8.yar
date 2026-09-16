rule TTP_XOR_QUAD_CurrentVersionRun_61e8 {
  strings:
    $key_61e8 = { 32 87 [2] 16 89 [2] 3d a5 [2] 13 87 [2] 07 9c [2] 08 86 [2] 16 9b [2] 14 9a [2] 0f 9c [2] 13 9b [2] 0f b4 }

  condition:
    any of them
}