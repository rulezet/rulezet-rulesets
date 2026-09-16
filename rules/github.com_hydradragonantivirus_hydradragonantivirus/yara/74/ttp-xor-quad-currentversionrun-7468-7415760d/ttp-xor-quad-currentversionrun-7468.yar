rule TTP_XOR_QUAD_CurrentVersionRun_7468 {
  strings:
    $key_7468 = { 27 07 [2] 03 09 [2] 28 25 [2] 06 07 [2] 12 1c [2] 1d 06 [2] 03 1b [2] 01 1a [2] 1a 1c [2] 06 1b [2] 1a 34 }

  condition:
    any of them
}