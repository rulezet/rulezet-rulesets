rule TTP_XOR_QUAD_CurrentVersionRun_2f73 {
  strings:
    $key_2f73 = { 7c 1c [2] 58 12 [2] 73 3e [2] 5d 1c [2] 49 07 [2] 46 1d [2] 58 00 [2] 5a 01 [2] 41 07 [2] 5d 00 [2] 41 2f }

  condition:
    any of them
}