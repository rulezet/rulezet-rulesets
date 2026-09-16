rule TTP_XOR_QUAD_CurrentVersionRun_5a0b {
  strings:
    $key_5a0b = { 09 64 [2] 2d 6a [2] 06 46 [2] 28 64 [2] 3c 7f [2] 33 65 [2] 2d 78 [2] 2f 79 [2] 34 7f [2] 28 78 [2] 34 57 }

  condition:
    any of them
}