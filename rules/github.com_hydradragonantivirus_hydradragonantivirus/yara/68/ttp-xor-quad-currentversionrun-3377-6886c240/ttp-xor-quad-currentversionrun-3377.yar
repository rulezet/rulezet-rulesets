rule TTP_XOR_QUAD_CurrentVersionRun_3377 {
  strings:
    $key_3377 = { 60 18 [2] 44 16 [2] 6f 3a [2] 41 18 [2] 55 03 [2] 5a 19 [2] 44 04 [2] 46 05 [2] 5d 03 [2] 41 04 [2] 5d 2b }

  condition:
    any of them
}