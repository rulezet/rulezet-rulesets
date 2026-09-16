rule TTP_XOR_QUAD_CurrentVersionRun_6649 {
  strings:
    $key_6649 = { 35 26 [2] 11 28 [2] 3a 04 [2] 14 26 [2] 00 3d [2] 0f 27 [2] 11 3a [2] 13 3b [2] 08 3d [2] 14 3a [2] 08 15 }

  condition:
    any of them
}