rule TTP_XOR_QUAD_CurrentVersionRun_6075 {
  strings:
    $key_6075 = { 33 1a [2] 17 14 [2] 3c 38 [2] 12 1a [2] 06 01 [2] 09 1b [2] 17 06 [2] 15 07 [2] 0e 01 [2] 12 06 [2] 0e 29 }

  condition:
    any of them
}