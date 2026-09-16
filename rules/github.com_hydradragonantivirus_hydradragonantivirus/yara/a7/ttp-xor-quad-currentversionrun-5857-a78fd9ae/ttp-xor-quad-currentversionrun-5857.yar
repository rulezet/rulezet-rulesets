rule TTP_XOR_QUAD_CurrentVersionRun_5857 {
  strings:
    $key_5857 = { 0b 38 [2] 2f 36 [2] 04 1a [2] 2a 38 [2] 3e 23 [2] 31 39 [2] 2f 24 [2] 2d 25 [2] 36 23 [2] 2a 24 [2] 36 0b }

  condition:
    any of them
}