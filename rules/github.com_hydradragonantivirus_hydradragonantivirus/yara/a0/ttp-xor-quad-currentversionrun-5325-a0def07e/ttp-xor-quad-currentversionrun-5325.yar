rule TTP_XOR_QUAD_CurrentVersionRun_5325 {
  strings:
    $key_5325 = { 00 4a [2] 24 44 [2] 0f 68 [2] 21 4a [2] 35 51 [2] 3a 4b [2] 24 56 [2] 26 57 [2] 3d 51 [2] 21 56 [2] 3d 79 }

  condition:
    any of them
}