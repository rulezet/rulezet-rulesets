rule TTP_XOR_QUAD_CurrentVersionRun_6175 {
  strings:
    $key_6175 = { 32 1a [2] 16 14 [2] 3d 38 [2] 13 1a [2] 07 01 [2] 08 1b [2] 16 06 [2] 14 07 [2] 0f 01 [2] 13 06 [2] 0f 29 }

  condition:
    any of them
}