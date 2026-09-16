rule TTP_XOR_QUAD_CurrentVersionRun_3373 {
  strings:
    $key_3373 = { 60 1c [2] 44 12 [2] 6f 3e [2] 41 1c [2] 55 07 [2] 5a 1d [2] 44 00 [2] 46 01 [2] 5d 07 [2] 41 00 [2] 5d 2f }

  condition:
    any of them
}