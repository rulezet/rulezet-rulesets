rule TTP_XOR_QUAD_CurrentVersionRun_640b {
  strings:
    $key_640b = { 37 64 [2] 13 6a [2] 38 46 [2] 16 64 [2] 02 7f [2] 0d 65 [2] 13 78 [2] 11 79 [2] 0a 7f [2] 16 78 [2] 0a 57 }

  condition:
    any of them
}