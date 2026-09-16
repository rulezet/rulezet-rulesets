rule TTP_XOR_QUAD_CurrentVersionRun_742b {
  strings:
    $key_742b = { 27 44 [2] 03 4a [2] 28 66 [2] 06 44 [2] 12 5f [2] 1d 45 [2] 03 58 [2] 01 59 [2] 1a 5f [2] 06 58 [2] 1a 77 }

  condition:
    any of them
}