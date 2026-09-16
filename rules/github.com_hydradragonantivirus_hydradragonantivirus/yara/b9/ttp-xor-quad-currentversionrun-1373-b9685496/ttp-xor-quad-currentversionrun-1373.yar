rule TTP_XOR_QUAD_CurrentVersionRun_1373 {
  strings:
    $key_1373 = { 40 1c [2] 64 12 [2] 4f 3e [2] 61 1c [2] 75 07 [2] 7a 1d [2] 64 00 [2] 66 01 [2] 7d 07 [2] 61 00 [2] 7d 2f }

  condition:
    any of them
}