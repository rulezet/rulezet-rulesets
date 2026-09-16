rule TTP_XOR_QUAD_CurrentVersionRun_5338 {
  strings:
    $key_5338 = { 00 57 [2] 24 59 [2] 0f 75 [2] 21 57 [2] 35 4c [2] 3a 56 [2] 24 4b [2] 26 4a [2] 3d 4c [2] 21 4b [2] 3d 64 }

  condition:
    any of them
}