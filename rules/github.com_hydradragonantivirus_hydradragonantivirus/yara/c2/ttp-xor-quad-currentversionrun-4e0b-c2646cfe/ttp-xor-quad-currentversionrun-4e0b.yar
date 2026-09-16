rule TTP_XOR_QUAD_CurrentVersionRun_4e0b {
  strings:
    $key_4e0b = { 1d 64 [2] 39 6a [2] 12 46 [2] 3c 64 [2] 28 7f [2] 27 65 [2] 39 78 [2] 3b 79 [2] 20 7f [2] 3c 78 [2] 20 57 }

  condition:
    any of them
}