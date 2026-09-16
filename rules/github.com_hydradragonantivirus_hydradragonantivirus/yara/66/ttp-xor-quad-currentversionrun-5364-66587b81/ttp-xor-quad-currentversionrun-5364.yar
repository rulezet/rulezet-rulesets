rule TTP_XOR_QUAD_CurrentVersionRun_5364 {
  strings:
    $key_5364 = { 00 0b [2] 24 05 [2] 0f 29 [2] 21 0b [2] 35 10 [2] 3a 0a [2] 24 17 [2] 26 16 [2] 3d 10 [2] 21 17 [2] 3d 38 }

  condition:
    any of them
}