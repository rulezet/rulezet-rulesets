rule TTP_XOR_QUAD_CurrentVersionRun_6f73 {
  strings:
    $key_6f73 = { 3c 1c [2] 18 12 [2] 33 3e [2] 1d 1c [2] 09 07 [2] 06 1d [2] 18 00 [2] 1a 01 [2] 01 07 [2] 1d 00 [2] 01 2f }

  condition:
    any of them
}