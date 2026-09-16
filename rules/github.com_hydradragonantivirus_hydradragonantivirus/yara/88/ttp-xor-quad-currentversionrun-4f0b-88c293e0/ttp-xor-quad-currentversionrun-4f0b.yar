rule TTP_XOR_QUAD_CurrentVersionRun_4f0b {
  strings:
    $key_4f0b = { 1c 64 [2] 38 6a [2] 13 46 [2] 3d 64 [2] 29 7f [2] 26 65 [2] 38 78 [2] 3a 79 [2] 21 7f [2] 3d 78 [2] 21 57 }

  condition:
    any of them
}