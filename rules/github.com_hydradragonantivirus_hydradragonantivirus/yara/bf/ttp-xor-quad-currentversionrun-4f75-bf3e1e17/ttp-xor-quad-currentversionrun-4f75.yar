rule TTP_XOR_QUAD_CurrentVersionRun_4f75 {
  strings:
    $key_4f75 = { 1c 1a [2] 38 14 [2] 13 38 [2] 3d 1a [2] 29 01 [2] 26 1b [2] 38 06 [2] 3a 07 [2] 21 01 [2] 3d 06 [2] 21 29 }

  condition:
    any of them
}