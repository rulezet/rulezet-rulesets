rule TTP_XOR_QUAD_CurrentVersionRun_1475 {
  strings:
    $key_1475 = { 47 1a [2] 63 14 [2] 48 38 [2] 66 1a [2] 72 01 [2] 7d 1b [2] 63 06 [2] 61 07 [2] 7a 01 [2] 66 06 [2] 7a 29 }

  condition:
    any of them
}