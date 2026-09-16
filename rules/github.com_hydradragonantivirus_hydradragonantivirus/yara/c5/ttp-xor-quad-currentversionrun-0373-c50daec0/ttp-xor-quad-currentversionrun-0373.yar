rule TTP_XOR_QUAD_CurrentVersionRun_0373 {
  strings:
    $key_0373 = { 50 1c [2] 74 12 [2] 5f 3e [2] 71 1c [2] 65 07 [2] 6a 1d [2] 74 00 [2] 76 01 [2] 6d 07 [2] 71 00 [2] 6d 2f }

  condition:
    any of them
}