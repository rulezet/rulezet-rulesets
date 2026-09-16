rule TTP_XOR_QUAD_CurrentVersionRun_7b0b {
  strings:
    $key_7b0b = { 28 64 [2] 0c 6a [2] 27 46 [2] 09 64 [2] 1d 7f [2] 12 65 [2] 0c 78 [2] 0e 79 [2] 15 7f [2] 09 78 [2] 15 57 }

  condition:
    any of them
}