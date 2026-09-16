rule TTP_XOR_QUAD_CurrentVersionRun_7f0b {
  strings:
    $key_7f0b = { 2c 64 [2] 08 6a [2] 23 46 [2] 0d 64 [2] 19 7f [2] 16 65 [2] 08 78 [2] 0a 79 [2] 11 7f [2] 0d 78 [2] 11 57 }

  condition:
    any of them
}