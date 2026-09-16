rule TTP_XOR_QUAD_CurrentVersionRun_4f25 {
  strings:
    $key_4f25 = { 1c 4a [2] 38 44 [2] 13 68 [2] 3d 4a [2] 29 51 [2] 26 4b [2] 38 56 [2] 3a 57 [2] 21 51 [2] 3d 56 [2] 21 79 }

  condition:
    any of them
}