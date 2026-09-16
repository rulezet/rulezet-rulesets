rule TTP_XOR_QUAD_CurrentVersionRun_6f66 {
  strings:
    $key_6f66 = { 3c 09 [2] 18 07 [2] 33 2b [2] 1d 09 [2] 09 12 [2] 06 08 [2] 18 15 [2] 1a 14 [2] 01 12 [2] 1d 15 [2] 01 3a }

  condition:
    any of them
}