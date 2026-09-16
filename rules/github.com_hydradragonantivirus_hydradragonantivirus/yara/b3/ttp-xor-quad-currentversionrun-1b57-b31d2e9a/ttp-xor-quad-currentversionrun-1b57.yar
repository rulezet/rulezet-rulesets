rule TTP_XOR_QUAD_CurrentVersionRun_1b57 {
  strings:
    $key_1b57 = { 48 38 [2] 6c 36 [2] 47 1a [2] 69 38 [2] 7d 23 [2] 72 39 [2] 6c 24 [2] 6e 25 [2] 75 23 [2] 69 24 [2] 75 0b }

  condition:
    any of them
}