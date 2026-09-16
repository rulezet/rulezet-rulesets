rule TTP_XOR_QUAD_CurrentVersionRun_5667 {
  strings:
    $key_5667 = { 05 08 [2] 21 06 [2] 0a 2a [2] 24 08 [2] 30 13 [2] 3f 09 [2] 21 14 [2] 23 15 [2] 38 13 [2] 24 14 [2] 38 3b }

  condition:
    any of them
}