rule TTP_XOR_QUAD_CurrentVersionRun_600b {
  strings:
    $key_600b = { 33 64 [2] 17 6a [2] 3c 46 [2] 12 64 [2] 06 7f [2] 09 65 [2] 17 78 [2] 15 79 [2] 0e 7f [2] 12 78 [2] 0e 57 }

  condition:
    any of them
}