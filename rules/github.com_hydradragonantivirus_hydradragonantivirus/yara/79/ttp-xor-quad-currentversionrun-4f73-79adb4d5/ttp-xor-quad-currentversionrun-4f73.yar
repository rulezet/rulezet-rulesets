rule TTP_XOR_QUAD_CurrentVersionRun_4f73 {
  strings:
    $key_4f73 = { 1c 1c [2] 38 12 [2] 13 3e [2] 3d 1c [2] 29 07 [2] 26 1d [2] 38 00 [2] 3a 01 [2] 21 07 [2] 3d 00 [2] 21 2f }

  condition:
    any of them
}