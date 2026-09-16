rule TTP_XOR_QUAD_CurrentVersionRun_4f78 {
  strings:
    $key_4f78 = { 1c 17 [2] 38 19 [2] 13 35 [2] 3d 17 [2] 29 0c [2] 26 16 [2] 38 0b [2] 3a 0a [2] 21 0c [2] 3d 0b [2] 21 24 }

  condition:
    any of them
}