rule TTP_XOR_QUAD_CurrentVersionRun_5675 {
  strings:
    $key_5675 = { 05 1a [2] 21 14 [2] 0a 38 [2] 24 1a [2] 30 01 [2] 3f 1b [2] 21 06 [2] 23 07 [2] 38 01 [2] 24 06 [2] 38 29 }

  condition:
    any of them
}