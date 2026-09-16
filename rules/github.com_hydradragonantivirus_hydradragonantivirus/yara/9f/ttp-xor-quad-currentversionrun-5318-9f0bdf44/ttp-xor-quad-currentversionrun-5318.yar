rule TTP_XOR_QUAD_CurrentVersionRun_5318 {
  strings:
    $key_5318 = { 00 77 [2] 24 79 [2] 0f 55 [2] 21 77 [2] 35 6c [2] 3a 76 [2] 24 6b [2] 26 6a [2] 3d 6c [2] 21 6b [2] 3d 44 }

  condition:
    any of them
}