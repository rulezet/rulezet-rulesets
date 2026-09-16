rule TTP_XOR_QUAD_CurrentVersionRun_750b {
  strings:
    $key_750b = { 26 64 [2] 02 6a [2] 29 46 [2] 07 64 [2] 13 7f [2] 1c 65 [2] 02 78 [2] 00 79 [2] 1b 7f [2] 07 78 [2] 1b 57 }

  condition:
    any of them
}