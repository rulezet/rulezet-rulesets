rule TTP_XOR_QUAD_CurrentVersionRun_53f8 {
  strings:
    $key_53f8 = { 00 97 [2] 24 99 [2] 0f b5 [2] 21 97 [2] 35 8c [2] 3a 96 [2] 24 8b [2] 26 8a [2] 3d 8c [2] 21 8b [2] 3d a4 }

  condition:
    any of them
}