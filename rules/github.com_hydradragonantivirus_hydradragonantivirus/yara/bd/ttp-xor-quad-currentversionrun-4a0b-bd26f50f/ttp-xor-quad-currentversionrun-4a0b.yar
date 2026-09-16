rule TTP_XOR_QUAD_CurrentVersionRun_4a0b {
  strings:
    $key_4a0b = { 19 64 [2] 3d 6a [2] 16 46 [2] 38 64 [2] 2c 7f [2] 23 65 [2] 3d 78 [2] 3f 79 [2] 24 7f [2] 38 78 [2] 24 57 }

  condition:
    any of them
}