rule TTP_XOR_QUAD_CurrentVersionRun_6168 {
  strings:
    $key_6168 = { 32 07 [2] 16 09 [2] 3d 25 [2] 13 07 [2] 07 1c [2] 08 06 [2] 16 1b [2] 14 1a [2] 0f 1c [2] 13 1b [2] 0f 34 }

  condition:
    any of them
}