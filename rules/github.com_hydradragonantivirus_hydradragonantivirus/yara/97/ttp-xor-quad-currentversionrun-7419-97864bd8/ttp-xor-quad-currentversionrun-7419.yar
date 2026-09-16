rule TTP_XOR_QUAD_CurrentVersionRun_7419 {
  strings:
    $key_7419 = { 27 76 [2] 03 78 [2] 28 54 [2] 06 76 [2] 12 6d [2] 1d 77 [2] 03 6a [2] 01 6b [2] 1a 6d [2] 06 6a [2] 1a 45 }

  condition:
    any of them
}