rule TTP_XOR_QUAD_CurrentVersionRun_7f57 {
  strings:
    $key_7f57 = { 2c 38 [2] 08 36 [2] 23 1a [2] 0d 38 [2] 19 23 [2] 16 39 [2] 08 24 [2] 0a 25 [2] 11 23 [2] 0d 24 [2] 11 0b }

  condition:
    any of them
}