rule TTP_XOR_QUAD_CurrentVersionRun_531b {
  strings:
    $key_531b = { 00 74 [2] 24 7a [2] 0f 56 [2] 21 74 [2] 35 6f [2] 3a 75 [2] 24 68 [2] 26 69 [2] 3d 6f [2] 21 68 [2] 3d 47 }

  condition:
    any of them
}