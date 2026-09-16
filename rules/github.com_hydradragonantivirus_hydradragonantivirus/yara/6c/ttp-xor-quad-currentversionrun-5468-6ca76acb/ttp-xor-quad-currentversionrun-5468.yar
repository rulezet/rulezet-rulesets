rule TTP_XOR_QUAD_CurrentVersionRun_5468 {
  strings:
    $key_5468 = { 07 07 [2] 23 09 [2] 08 25 [2] 26 07 [2] 32 1c [2] 3d 06 [2] 23 1b [2] 21 1a [2] 3a 1c [2] 26 1b [2] 3a 34 }

  condition:
    any of them
}