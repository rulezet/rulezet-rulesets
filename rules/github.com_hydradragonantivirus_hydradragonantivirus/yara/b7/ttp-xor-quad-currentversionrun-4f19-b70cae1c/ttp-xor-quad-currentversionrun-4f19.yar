rule TTP_XOR_QUAD_CurrentVersionRun_4f19 {
  strings:
    $key_4f19 = { 1c 76 [2] 38 78 [2] 13 54 [2] 3d 76 [2] 29 6d [2] 26 77 [2] 38 6a [2] 3a 6b [2] 21 6d [2] 3d 6a [2] 21 45 }

  condition:
    any of them
}