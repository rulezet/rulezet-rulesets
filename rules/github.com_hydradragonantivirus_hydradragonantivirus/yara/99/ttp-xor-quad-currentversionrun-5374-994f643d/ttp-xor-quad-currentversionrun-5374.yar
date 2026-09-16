rule TTP_XOR_QUAD_CurrentVersionRun_5374 {
  strings:
    $key_5374 = { 00 1b [2] 24 15 [2] 0f 39 [2] 21 1b [2] 35 00 [2] 3a 1a [2] 24 07 [2] 26 06 [2] 3d 00 [2] 21 07 [2] 3d 28 }

  condition:
    any of them
}