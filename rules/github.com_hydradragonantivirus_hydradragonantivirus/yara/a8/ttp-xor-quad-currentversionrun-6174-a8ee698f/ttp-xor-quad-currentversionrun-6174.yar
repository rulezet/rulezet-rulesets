rule TTP_XOR_QUAD_CurrentVersionRun_6174 {
  strings:
    $key_6174 = { 32 1b [2] 16 15 [2] 3d 39 [2] 13 1b [2] 07 00 [2] 08 1a [2] 16 07 [2] 14 06 [2] 0f 00 [2] 13 07 [2] 0f 28 }

  condition:
    any of them
}