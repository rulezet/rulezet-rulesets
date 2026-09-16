rule TTP_XOR_QUAD_CurrentVersionRun_531a {
  strings:
    $key_531a = { 00 75 [2] 24 7b [2] 0f 57 [2] 21 75 [2] 35 6e [2] 3a 74 [2] 24 69 [2] 26 68 [2] 3d 6e [2] 21 69 [2] 3d 46 }

  condition:
    any of them
}