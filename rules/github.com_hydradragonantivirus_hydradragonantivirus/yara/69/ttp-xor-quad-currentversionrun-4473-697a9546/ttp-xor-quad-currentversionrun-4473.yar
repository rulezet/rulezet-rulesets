rule TTP_XOR_QUAD_CurrentVersionRun_4473 {
  strings:
    $key_4473 = { 17 1c [2] 33 12 [2] 18 3e [2] 36 1c [2] 22 07 [2] 2d 1d [2] 33 00 [2] 31 01 [2] 2a 07 [2] 36 00 [2] 2a 2f }

  condition:
    any of them
}