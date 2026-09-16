rule TTP_XOR_QUAD_CurrentVersionRun_6373 {
  strings:
    $key_6373 = { 30 1c [2] 14 12 [2] 3f 3e [2] 11 1c [2] 05 07 [2] 0a 1d [2] 14 00 [2] 16 01 [2] 0d 07 [2] 11 00 [2] 0d 2f }

  condition:
    any of them
}