rule TTP_XOR_QUAD_CurrentVersionRun_4fe4 {
  strings:
    $key_4fe4 = { 1c 8b [2] 38 85 [2] 13 a9 [2] 3d 8b [2] 29 90 [2] 26 8a [2] 38 97 [2] 3a 96 [2] 21 90 [2] 3d 97 [2] 21 b8 }

  condition:
    any of them
}