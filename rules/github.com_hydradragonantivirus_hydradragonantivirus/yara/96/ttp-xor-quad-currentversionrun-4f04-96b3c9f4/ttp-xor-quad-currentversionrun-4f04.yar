rule TTP_XOR_QUAD_CurrentVersionRun_4f04 {
  strings:
    $key_4f04 = { 1c 6b [2] 38 65 [2] 13 49 [2] 3d 6b [2] 29 70 [2] 26 6a [2] 38 77 [2] 3a 76 [2] 21 70 [2] 3d 77 [2] 21 58 }

  condition:
    any of them
}