rule TTP_XOR_QUAD_CurrentVersionRun_7417 {
  strings:
    $key_7417 = { 27 78 [2] 03 76 [2] 28 5a [2] 06 78 [2] 12 63 [2] 1d 79 [2] 03 64 [2] 01 65 [2] 1a 63 [2] 06 64 [2] 1a 4b }

  condition:
    any of them
}