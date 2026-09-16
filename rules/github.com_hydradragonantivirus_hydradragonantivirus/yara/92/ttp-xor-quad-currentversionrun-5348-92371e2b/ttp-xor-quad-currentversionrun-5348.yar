rule TTP_XOR_QUAD_CurrentVersionRun_5348 {
  strings:
    $key_5348 = { 00 27 [2] 24 29 [2] 0f 05 [2] 21 27 [2] 35 3c [2] 3a 26 [2] 24 3b [2] 26 3a [2] 3d 3c [2] 21 3b [2] 3d 14 }

  condition:
    any of them
}