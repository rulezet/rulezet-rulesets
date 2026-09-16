rule TTP_XOR_QUAD_CurrentVersionRun_6857 {
  strings:
    $key_6857 = { 3b 38 [2] 1f 36 [2] 34 1a [2] 1a 38 [2] 0e 23 [2] 01 39 [2] 1f 24 [2] 1d 25 [2] 06 23 [2] 1a 24 [2] 06 0b }

  condition:
    any of them
}