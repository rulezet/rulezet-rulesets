rule TTP_XOR_QUAD_CurrentVersionRun_3375 {
  strings:
    $key_3375 = { 60 1a [2] 44 14 [2] 6f 38 [2] 41 1a [2] 55 01 [2] 5a 1b [2] 44 06 [2] 46 07 [2] 5d 01 [2] 41 06 [2] 5d 29 }

  condition:
    any of them
}