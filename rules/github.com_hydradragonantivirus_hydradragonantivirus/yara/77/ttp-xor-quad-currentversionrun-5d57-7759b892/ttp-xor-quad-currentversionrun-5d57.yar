rule TTP_XOR_QUAD_CurrentVersionRun_5d57 {
  strings:
    $key_5d57 = { 0e 38 [2] 2a 36 [2] 01 1a [2] 2f 38 [2] 3b 23 [2] 34 39 [2] 2a 24 [2] 28 25 [2] 33 23 [2] 2f 24 [2] 33 0b }

  condition:
    any of them
}