rule TTP_XOR_QUAD_CurrentVersionRun_5378 {
  strings:
    $key_5378 = { 00 17 [2] 24 19 [2] 0f 35 [2] 21 17 [2] 35 0c [2] 3a 16 [2] 24 0b [2] 26 0a [2] 3d 0c [2] 21 0b [2] 3d 24 }

  condition:
    any of them
}