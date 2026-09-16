rule TTP_XOR_QUAD_CurrentVersionRun_6457 {
  strings:
    $key_6457 = { 37 38 [2] 13 36 [2] 38 1a [2] 16 38 [2] 02 23 [2] 0d 39 [2] 13 24 [2] 11 25 [2] 0a 23 [2] 16 24 [2] 0a 0b }

  condition:
    any of them
}