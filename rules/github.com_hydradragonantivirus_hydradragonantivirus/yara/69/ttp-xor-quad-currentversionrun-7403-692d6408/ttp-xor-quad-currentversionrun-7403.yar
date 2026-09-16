rule TTP_XOR_QUAD_CurrentVersionRun_7403 {
  strings:
    $key_7403 = { 27 6c [2] 03 62 [2] 28 4e [2] 06 6c [2] 12 77 [2] 1d 6d [2] 03 70 [2] 01 71 [2] 1a 77 [2] 06 70 [2] 1a 5f }

  condition:
    any of them
}