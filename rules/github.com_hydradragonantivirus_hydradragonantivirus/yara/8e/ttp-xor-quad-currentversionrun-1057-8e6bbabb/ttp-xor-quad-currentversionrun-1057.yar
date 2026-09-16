rule TTP_XOR_QUAD_CurrentVersionRun_1057 {
  strings:
    $key_1057 = { 43 38 [2] 67 36 [2] 4c 1a [2] 62 38 [2] 76 23 [2] 79 39 [2] 67 24 [2] 65 25 [2] 7e 23 [2] 62 24 [2] 7e 0b }

  condition:
    any of them
}