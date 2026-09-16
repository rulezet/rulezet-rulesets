rule TTP_XOR_QUAD_CurrentVersionRun_5365 {
  strings:
    $key_5365 = { 00 0a [2] 24 04 [2] 0f 28 [2] 21 0a [2] 35 11 [2] 3a 0b [2] 24 16 [2] 26 17 [2] 3d 11 [2] 21 16 [2] 3d 39 }

  condition:
    any of them
}