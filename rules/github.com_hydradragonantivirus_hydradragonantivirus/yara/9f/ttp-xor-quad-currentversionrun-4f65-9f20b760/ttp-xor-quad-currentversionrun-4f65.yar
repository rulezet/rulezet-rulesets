rule TTP_XOR_QUAD_CurrentVersionRun_4f65 {
  strings:
    $key_4f65 = { 1c 0a [2] 38 04 [2] 13 28 [2] 3d 0a [2] 29 11 [2] 26 0b [2] 38 16 [2] 3a 17 [2] 21 11 [2] 3d 16 [2] 21 39 }

  condition:
    any of them
}