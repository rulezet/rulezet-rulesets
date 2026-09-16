rule TTP_XOR_QUAD_CurrentVersionRun_7466 {
  strings:
    $key_7466 = { 27 09 [2] 03 07 [2] 28 2b [2] 06 09 [2] 12 12 [2] 1d 08 [2] 03 15 [2] 01 14 [2] 1a 12 [2] 06 15 [2] 1a 3a }

  condition:
    any of them
}