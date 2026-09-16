rule TTP_XOR_QUAD_CurrentVersionRun_6169 {
  strings:
    $key_6169 = { 32 06 [2] 16 08 [2] 3d 24 [2] 13 06 [2] 07 1d [2] 08 07 [2] 16 1a [2] 14 1b [2] 0f 1d [2] 13 1a [2] 0f 35 }

  condition:
    any of them
}