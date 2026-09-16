rule TTP_XOR_QUAD_CurrentVersionRun_1d57 {
  strings:
    $key_1d57 = { 4e 38 [2] 6a 36 [2] 41 1a [2] 6f 38 [2] 7b 23 [2] 74 39 [2] 6a 24 [2] 68 25 [2] 73 23 [2] 6f 24 [2] 73 0b }

  condition:
    any of them
}