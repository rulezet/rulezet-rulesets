rule TTP_XOR_QUAD_CurrentVersionRun_6f77 {
  strings:
    $key_6f77 = { 3c 18 [2] 18 16 [2] 33 3a [2] 1d 18 [2] 09 03 [2] 06 19 [2] 18 04 [2] 1a 05 [2] 01 03 [2] 1d 04 [2] 01 2b }

  condition:
    any of them
}