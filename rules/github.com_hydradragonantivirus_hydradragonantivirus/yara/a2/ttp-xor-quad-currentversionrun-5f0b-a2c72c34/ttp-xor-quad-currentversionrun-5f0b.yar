rule TTP_XOR_QUAD_CurrentVersionRun_5f0b {
  strings:
    $key_5f0b = { 0c 64 [2] 28 6a [2] 03 46 [2] 2d 64 [2] 39 7f [2] 36 65 [2] 28 78 [2] 2a 79 [2] 31 7f [2] 2d 78 [2] 31 57 }

  condition:
    any of them
}