rule TTP_XOR_QUAD_CurrentVersionRun_7c57 {
  strings:
    $key_7c57 = { 2f 38 [2] 0b 36 [2] 20 1a [2] 0e 38 [2] 1a 23 [2] 15 39 [2] 0b 24 [2] 09 25 [2] 12 23 [2] 0e 24 [2] 12 0b }

  condition:
    any of them
}