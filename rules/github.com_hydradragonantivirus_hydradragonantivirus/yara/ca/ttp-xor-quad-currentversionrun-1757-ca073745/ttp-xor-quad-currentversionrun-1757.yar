rule TTP_XOR_QUAD_CurrentVersionRun_1757 {
  strings:
    $key_1757 = { 44 38 [2] 60 36 [2] 4b 1a [2] 65 38 [2] 71 23 [2] 7e 39 [2] 60 24 [2] 62 25 [2] 79 23 [2] 65 24 [2] 79 0b }

  condition:
    any of them
}