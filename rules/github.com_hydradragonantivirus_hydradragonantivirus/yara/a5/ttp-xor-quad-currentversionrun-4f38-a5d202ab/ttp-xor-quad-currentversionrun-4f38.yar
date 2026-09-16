rule TTP_XOR_QUAD_CurrentVersionRun_4f38 {
  strings:
    $key_4f38 = { 1c 57 [2] 38 59 [2] 13 75 [2] 3d 57 [2] 29 4c [2] 26 56 [2] 38 4b [2] 3a 4a [2] 21 4c [2] 3d 4b [2] 21 64 }

  condition:
    any of them
}