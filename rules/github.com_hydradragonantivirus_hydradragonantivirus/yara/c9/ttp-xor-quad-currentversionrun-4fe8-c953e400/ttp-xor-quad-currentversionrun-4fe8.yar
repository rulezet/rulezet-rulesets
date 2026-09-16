rule TTP_XOR_QUAD_CurrentVersionRun_4fe8 {
  strings:
    $key_4fe8 = { 1c 87 [2] 38 89 [2] 13 a5 [2] 3d 87 [2] 29 9c [2] 26 86 [2] 38 9b [2] 3a 9a [2] 21 9c [2] 3d 9b [2] 21 b4 }

  condition:
    any of them
}