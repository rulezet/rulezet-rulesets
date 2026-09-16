rule TTP_XOR_QUAD_CurrentVersionRun_7456 {
  strings:
    $key_7456 = { 27 39 [2] 03 37 [2] 28 1b [2] 06 39 [2] 12 22 [2] 1d 38 [2] 03 25 [2] 01 24 [2] 1a 22 [2] 06 25 [2] 1a 0a }

  condition:
    any of them
}