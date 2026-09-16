rule TTP_XOR_QUAD_CurrentVersionRun_5324 {
  strings:
    $key_5324 = { 00 4b [2] 24 45 [2] 0f 69 [2] 21 4b [2] 35 50 [2] 3a 4a [2] 24 57 [2] 26 56 [2] 3d 50 [2] 21 57 [2] 3d 78 }

  condition:
    any of them
}