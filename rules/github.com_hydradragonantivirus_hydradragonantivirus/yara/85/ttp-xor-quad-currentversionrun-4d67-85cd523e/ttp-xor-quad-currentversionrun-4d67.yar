rule TTP_XOR_QUAD_CurrentVersionRun_4d67 {
  strings:
    $key_4d67 = { 1e 08 [2] 3a 06 [2] 11 2a [2] 3f 08 [2] 2b 13 [2] 24 09 [2] 3a 14 [2] 38 15 [2] 23 13 [2] 3f 14 [2] 23 3b }

  condition:
    any of them
}