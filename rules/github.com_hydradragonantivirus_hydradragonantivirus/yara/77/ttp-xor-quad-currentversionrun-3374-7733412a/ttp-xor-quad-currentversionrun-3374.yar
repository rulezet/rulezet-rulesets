rule TTP_XOR_QUAD_CurrentVersionRun_3374 {
  strings:
    $key_3374 = { 60 1b [2] 44 15 [2] 6f 39 [2] 41 1b [2] 55 00 [2] 5a 1a [2] 44 07 [2] 46 06 [2] 5d 00 [2] 41 07 [2] 5d 28 }

  condition:
    any of them
}