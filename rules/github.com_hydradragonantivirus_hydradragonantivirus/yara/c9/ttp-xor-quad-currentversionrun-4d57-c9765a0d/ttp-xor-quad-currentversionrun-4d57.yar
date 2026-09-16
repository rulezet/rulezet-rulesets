rule TTP_XOR_QUAD_CurrentVersionRun_4d57 {
  strings:
    $key_4d57 = { 1e 38 [2] 3a 36 [2] 11 1a [2] 3f 38 [2] 2b 23 [2] 24 39 [2] 3a 24 [2] 38 25 [2] 23 23 [2] 3f 24 [2] 23 0b }

  condition:
    any of them
}