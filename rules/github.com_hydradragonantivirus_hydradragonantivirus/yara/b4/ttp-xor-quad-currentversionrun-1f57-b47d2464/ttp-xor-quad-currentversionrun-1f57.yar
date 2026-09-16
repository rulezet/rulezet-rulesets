rule TTP_XOR_QUAD_CurrentVersionRun_1f57 {
  strings:
    $key_1f57 = { 4c 38 [2] 68 36 [2] 43 1a [2] 6d 38 [2] 79 23 [2] 76 39 [2] 68 24 [2] 6a 25 [2] 71 23 [2] 6d 24 [2] 71 0b }

  condition:
    any of them
}