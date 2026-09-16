rule TTP_XOR_QUAD_CurrentVersionRun_7418 {
  strings:
    $key_7418 = { 27 77 [2] 03 79 [2] 28 55 [2] 06 77 [2] 12 6c [2] 1d 76 [2] 03 6b [2] 01 6a [2] 1a 6c [2] 06 6b [2] 1a 44 }

  condition:
    any of them
}